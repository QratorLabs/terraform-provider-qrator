package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

var (
	_ resource.Resource                = &ServiceStatusResource{}
	_ resource.ResourceWithImportState = &ServiceStatusResource{}
)

type ServiceStatusResource struct {
	client *client.QratorClient
}

func NewServiceStatusResource() resource.Resource {
	return &ServiceStatusResource{}
}

func (r *ServiceStatusResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_status"
}

func (r *ServiceStatusResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the status of a service in Qrator.",
		Attributes: map[string]schema.Attribute{
			"service_id": schema.Int64Attribute{
				Description: "The service ID. Changing this forces a new resource.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"status": schema.StringAttribute{
				Description: "Service status: online or offline.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("online"),
				Validators:  []validator.String{stringvalidator.OneOf("online", "offline")},
			},
		},
	}
}

func (r *ServiceStatusResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ServiceStatusResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected numeric service_id")
		return
	}
	resp.State.SetAttribute(ctx, path.Root("service_id"), id)
}

func (r *ServiceStatusResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var serviceID types.Int64
	var status types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("service_id"), &serviceID)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("status"), &status)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := entityService.apiPath(serviceID.ValueInt64())

	if !status.IsNull() && !status.IsUnknown() {
		if _, err := r.client.MakeRequest(ctx, apiPath, "status_set", status.ValueString()); err != nil {
			resp.Diagnostics.AddError("Failed to set service status", err.Error())
			return
		}
	}

	r.readAndSetState(ctx, serviceID.ValueInt64(), &resp.Diagnostics, &resp.State)
}

func (r *ServiceStatusResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var serviceID types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("service_id"), &serviceID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.readAndSetState(ctx, serviceID.ValueInt64(), &resp.Diagnostics, &resp.State)
}

func (r *ServiceStatusResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var serviceID types.Int64
	var status types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("service_id"), &serviceID)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("status"), &status)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := entityService.apiPath(serviceID.ValueInt64())

	if _, err := r.client.MakeRequest(ctx, apiPath, "status_set", status.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to set service status", err.Error())
		return
	}

	r.readAndSetState(ctx, serviceID.ValueInt64(), &resp.Diagnostics, &resp.State)
}

func (r *ServiceStatusResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var serviceID types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("service_id"), &serviceID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := entityService.apiPath(serviceID.ValueInt64())
	if _, err := r.client.MakeRequest(ctx, apiPath, "status_set", "online"); err != nil {
		resp.Diagnostics.AddError("Failed to reset service status", err.Error())
	}
}

func (r *ServiceStatusResource) readAndSetState(ctx context.Context, serviceID int64, diags *diag.Diagnostics, state *tfsdk.State) {
	apiPath := entityService.apiPath(serviceID)

	v, err := r.client.MakeRequest(ctx, apiPath, "status_get", nil)
	if err != nil {
		diags.AddError("Failed to read service status", err.Error())
		return
	}

	var status string
	if err := json.Unmarshal(v, &status); err != nil {
		diags.AddError("Failed to parse service status", err.Error())
		return
	}

	diags.Append(state.SetAttribute(ctx, path.Root("service_id"), types.Int64Value(serviceID))...)
	diags.Append(state.SetAttribute(ctx, path.Root("status"), types.StringValue(status))...)

	tflog.Debug(ctx, fmt.Sprintf("Read service %d status: %s", serviceID, status))
}
