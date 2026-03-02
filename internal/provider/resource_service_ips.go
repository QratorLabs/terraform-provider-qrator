package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

var (
	_ resource.Resource                   = &ServiceIPsResource{}
	_ resource.ResourceWithImportState    = &ServiceIPsResource{}
	_ resource.ResourceWithValidateConfig = &ServiceIPsResource{}
)

type ServiceIPsResource struct {
	client *client.QratorClient
}

func NewServiceIPsResource() resource.Resource {
	return &ServiceIPsResource{}
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func (r *ServiceIPsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_ips"
}

func (r *ServiceIPsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the upstream IP addresses for a service in Qrator.",
		Attributes: map[string]schema.Attribute{
			"service_id": schema.Int64Attribute{
				Description: "The service ID.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"ips": schema.ListAttribute{
				Description: "List of upstream IP addresses.",
				Required:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func (r *ServiceIPsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.QratorClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.QratorClient, got: %T.", req.ProviderData))
		return
	}
	r.client = c
}

// ---------------------------------------------------------------------------
// ValidateConfig
// ---------------------------------------------------------------------------

func (r *ServiceIPsResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var ips types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("ips"), &ips)...)
	if resp.Diagnostics.HasError() || ips.IsNull() || ips.IsUnknown() {
		return
	}

	var ipList []types.String
	resp.Diagnostics.Append(ips.ElementsAs(ctx, &ipList, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	seen := make(map[string]bool)
	for i, ip := range ipList {
		if ip.IsUnknown() {
			continue
		}
		v := ip.ValueString()
		if seen[v] {
			resp.Diagnostics.AddAttributeError(path.Root("ips").AtListIndex(i),
				"Duplicate IP", fmt.Sprintf("Duplicate IP address %q", v))
		}
		seen[v] = true
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func (r *ServiceIPsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected numeric service ID")
		return
	}
	resp.State.SetAttribute(ctx, path.Root("service_id"), id)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func (r *ServiceIPsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var serviceID types.Int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("service_id"), &serviceID)...)
	var ips []string
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("ips"), &ips)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := entityService.apiPath(serviceID.ValueInt64())
	if _, err := r.client.MakeRequest(ctx, apiPath, "service_ip_set", ips); err != nil {
		resp.Diagnostics.AddError("Failed to set service IPs", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("service_id"), serviceID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ips"), ips)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *ServiceIPsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var serviceID types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("service_id"), &serviceID)...)
	var stateIPs []string
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("ips"), &stateIPs)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiIPs, err := r.readIPs(ctx, serviceID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read service IPs", err.Error())
		return
	}

	// Reconcile: preserve state ordering for IPs that still exist in API,
	// append any new API IPs at the end.
	apiSet := make(map[string]bool, len(apiIPs))
	for _, ip := range apiIPs {
		apiSet[ip] = true
	}

	seen := make(map[string]bool, len(apiIPs))
	reconciled := make([]string, 0, len(apiIPs))

	for _, ip := range stateIPs {
		if apiSet[ip] {
			reconciled = append(reconciled, ip)
			seen[ip] = true
		}
	}
	for _, ip := range apiIPs {
		if !seen[ip] {
			reconciled = append(reconciled, ip)
		}
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("service_id"), serviceID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ips"), reconciled)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *ServiceIPsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var serviceID types.Int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("service_id"), &serviceID)...)
	var ips []string
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("ips"), &ips)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := entityService.apiPath(serviceID.ValueInt64())
	if _, err := r.client.MakeRequest(ctx, apiPath, "service_ip_set", ips); err != nil {
		resp.Diagnostics.AddError("Failed to set service IPs", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("service_id"), serviceID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ips"), ips)...)
}

// ---------------------------------------------------------------------------
// Delete — clear the IP list
// ---------------------------------------------------------------------------

func (r *ServiceIPsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var serviceID types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("service_id"), &serviceID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := entityService.apiPath(serviceID.ValueInt64())
	if _, err := r.client.MakeRequest(ctx, apiPath, "service_ip_set", []string{}); err != nil {
		resp.Diagnostics.AddError("Failed to clear service IPs", err.Error())
		return
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *ServiceIPsResource) readIPs(ctx context.Context, serviceID int64) ([]string, error) {
	apiPath := entityService.apiPath(serviceID)

	v, err := r.client.MakeRequest(ctx, apiPath, "service_ip_get", nil)
	if err != nil {
		return nil, fmt.Errorf("service_ip_get failed: %w", err)
	}

	var ips []string
	if err := json.Unmarshal(v, &ips); err != nil {
		return nil, fmt.Errorf("failed to parse service_ip_get response: %w", err)
	}

	tflog.Debug(ctx, fmt.Sprintf("Read service %d IPs: %v", serviceID, ips))
	return ips, nil
}
