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
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

var (
	_ resource.Resource                   = &EntityResource{}
	_ resource.ResourceWithImportState    = &EntityResource{}
	_ resource.ResourceWithValidateConfig = &EntityResource{}
)

// EntityResource manages a domain or service entity.
type EntityResource struct {
	client client.QratorClientAPI
	entity entityKind
}

func NewDomainResource() resource.Resource {
	return &EntityResource{entity: entityDomain}
}

func NewServiceResource() resource.Resource {
	return &EntityResource{entity: entityService}
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func (r *EntityResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.entity.String()
}

func (r *EntityResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := map[string]schema.Attribute{
		"id": schema.Int64Attribute{
			Description: fmt.Sprintf("The %s ID.", r.entity),
			Computed:    true,
			PlanModifiers: []planmodifier.Int64{
				int64planmodifier.UseStateForUnknown(),
			},
		},
		"client_id": schema.Int64Attribute{
			Description: "The client ID used when creating the entity.",
			Required:    true,
		},
		"name": schema.StringAttribute{
			Description: fmt.Sprintf("The %s name.", r.entity),
			Required:    true,
		},
		"maintenance_until": schema.Int64Attribute{
			Description: "Unix timestamp (seconds) until which maintenance mode is active. " +
				"Null or omitted means maintenance mode is disabled.",
			Optional: true,
			Computed: true,
		},
	}

	if r.entity == entityService {
		attrs["status"] = schema.StringAttribute{
			Description: "Service status: online or offline.",
			Optional:    true,
			Computed:    true,
			Validators:  []validator.String{stringvalidator.OneOf("online", "offline")},
		}
		attrs["ips"] = schema.ListAttribute{
			Description: "List of upstream IP addresses for the service. Required when creating a new service.",
			Optional:    true,
			Computed:    true,
			ElementType: types.StringType,
		}
	}

	resp.Schema = schema.Schema{
		Description: fmt.Sprintf("Manages a %s in Qrator.", r.entity),
		Attributes:  attrs,
	}
}

// ---------------------------------------------------------------------------
// ValidateConfig
// ---------------------------------------------------------------------------

func (r *EntityResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	if r.entity != entityService {
		return
	}

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
// Configure
// ---------------------------------------------------------------------------

func (r *EntityResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
// ImportState
// ---------------------------------------------------------------------------

func (r *EntityResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", fmt.Sprintf("Expected numeric %s ID", r.entity))
		return
	}
	resp.State.SetAttribute(ctx, path.Root("id"), id)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func (r *EntityResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var clientID types.Int64
	var name types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("client_id"), &clientID)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("name"), &name)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read service-specific attributes.
	var ips []string
	var planStatus types.String
	if r.entity == entityService {
		var ipsList types.List
		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("ips"), &ipsList)...)
		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("status"), &planStatus)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if ipsList.IsNull() || ipsList.IsUnknown() {
			resp.Diagnostics.AddError("Missing IPs",
				"At least one upstream IP address is required when creating a service. Set the 'ips' attribute.")
			return
		}
		resp.Diagnostics.Append(ipsList.ElementsAs(ctx, &ips, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(ips) == 0 {
			resp.Diagnostics.AddError("Empty IPs",
				"At least one upstream IP address is required when creating a service.")
			return
		}
	}

	// Call {entity}_create on /request/client/{client_id}.
	createPath := r.entity.clientPath(clientID.ValueInt64())
	createParams := r.entity.createParams(name.ValueString(), ips)
	result, err := r.client.MakeRequest(ctx, createPath, r.entity.createMethod(), createParams)
	if err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Failed to create %s", r.entity), err.Error())
		return
	}

	// Parse the returned entity ID (Number).
	var entityID int64
	if err := json.Unmarshal(result, &entityID); err != nil {
		resp.Diagnostics.AddError("Failed to parse created entity ID", err.Error())
		return
	}

	// For service: set status (defaults to "online" if not specified).
	if r.entity == entityService {
		apiPath := r.entity.apiPath(entityID)
		statusVal := "online"
		if !planStatus.IsNull() && !planStatus.IsUnknown() {
			statusVal = planStatus.ValueString()
		}
		if _, err := r.client.MakeRequest(ctx, apiPath, "status_set", []interface{}{statusVal}); err != nil {
			resp.Diagnostics.AddError("Failed to set service status", err.Error())
			return
		}
	}

	// Set maintenance mode if explicitly requested.
	var planUntil types.Int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("maintenance_until"), &planUntil)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !planUntil.IsNull() && !planUntil.IsUnknown() {
		apiPath := r.entity.apiPath(entityID)
		params := maintenanceModeResult{Until: planUntil.ValueInt64Pointer()}
		if _, err := r.client.MakeRequest(ctx, apiPath, "maintenance_mode_set", params); err != nil {
			resp.Diagnostics.AddError("Failed to set maintenance mode", err.Error())
			return
		}
	}

	// Read back from API and set state.
	r.readAndSetState(ctx, entityID, &resp.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Preserve client_id in state.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("client_id"), clientID)...)

	// For service: set IPs and override status (API may return "pending" during transition).
	if r.entity == entityService {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ips"), ips)...)
		statusVal := "online"
		if !planStatus.IsNull() && !planStatus.IsUnknown() {
			statusVal = planStatus.ValueString()
		}
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("status"), statusVal)...)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *EntityResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var id types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("id"), &id)...)
	if resp.Diagnostics.HasError() {
		return
	}

	entityID := id.ValueInt64()
	r.readAndSetState(ctx, entityID, &resp.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// For service: read IPs from API and reconcile with state order.
	if r.entity == entityService {
		var stateIPs []string
		resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("ips"), &stateIPs)...)
		if resp.Diagnostics.HasError() {
			return
		}

		apiIPs, err := r.readIPs(ctx, entityID)
		if err != nil {
			resp.Diagnostics.AddError("Failed to read service IPs", err.Error())
			return
		}

		reconciled := reconcileIPs(stateIPs, apiIPs)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ips"), reconciled)...)
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *EntityResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var id types.Int64
	var planName types.String
	var stateName types.String
	var planClientID types.Int64

	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("id"), &id)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("client_id"), &planClientID)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("name"), &planName)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("name"), &stateName)...)
	if resp.Diagnostics.HasError() {
		return
	}

	entityID := id.ValueInt64()
	apiPath := r.entity.apiPath(entityID)

	// For service: read status from plan and state.
	var planStatusStr, stateStatusStr string
	if r.entity == entityService {
		var planStatus, stateStatus types.String
		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("status"), &planStatus)...)
		resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("status"), &stateStatus)...)
		if resp.Diagnostics.HasError() {
			return
		}
		planStatusStr = planStatus.ValueString()
		stateStatusStr = stateStatus.ValueString()

		// If going online, do it first so _set methods work.
		if planStatusStr == "online" && stateStatusStr != "online" {
			if _, err := r.client.MakeRequest(ctx, apiPath, "status_set", []interface{}{"online"}); err != nil {
				resp.Diagnostics.AddError("Failed to set service status", err.Error())
				return
			}
		}
	}

	// Update name if changed.
	if !planName.IsNull() && !planName.IsUnknown() &&
		(stateName.IsNull() || planName.ValueString() != stateName.ValueString()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "name_set", planName.ValueString()); err != nil {
			resp.Diagnostics.AddError(fmt.Sprintf("Failed to set %s name", r.entity), err.Error())
			return
		}
	}

	// For service: update IPs if changed, then handle offline transition.
	if r.entity == entityService {
		var planIPs, stateIPs []string
		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("ips"), &planIPs)...)
		resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("ips"), &stateIPs)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if !stringSlicesEqual(planIPs, stateIPs) {
			if _, err := r.client.MakeRequest(ctx, apiPath, "service_ip_set", planIPs); err != nil {
				resp.Diagnostics.AddError("Failed to set service IPs", err.Error())
				return
			}
		}

		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ips"), planIPs)...)

		// If going offline, do it last (after all other _set calls).
		if planStatusStr == "offline" && stateStatusStr != "offline" {
			if _, err := r.client.MakeRequest(ctx, apiPath, "status_set", []interface{}{"offline"}); err != nil {
				resp.Diagnostics.AddError("Failed to set service status", err.Error())
				return
			}
		}
	}

	// Update maintenance mode if changed.
	var planUntil, stateUntil types.Int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("maintenance_until"), &planUntil)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("maintenance_until"), &stateUntil)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !planUntil.Equal(stateUntil) {
		var until *int64
		if !planUntil.IsNull() && !planUntil.IsUnknown() {
			until = planUntil.ValueInt64Pointer()
		}
		params := maintenanceModeResult{Until: until}
		if _, err := r.client.MakeRequest(ctx, apiPath, "maintenance_mode_set", params); err != nil {
			resp.Diagnostics.AddError("Failed to set maintenance mode", err.Error())
			return
		}
	}

	r.readAndSetState(ctx, entityID, &resp.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Preserve client_id in state.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("client_id"), planClientID)...)
}

// ---------------------------------------------------------------------------
// Delete — no-op (entity is not deleted)
// ---------------------------------------------------------------------------

func (r *EntityResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// maintenanceModeResult is the API response/param shape for maintenance_mode_get/set.
type maintenanceModeResult struct {
	Until *int64 `json:"until"`
}

// readAndSetState reads name, maintenance mode, and status (for services) from the API.
func (r *EntityResource) readAndSetState(ctx context.Context, entityID int64, state *tfsdk.State, diags *diag.Diagnostics) {
	apiPath := r.entity.apiPath(entityID)

	// Read name.
	v, err := r.client.MakeRequest(ctx, apiPath, "name_get", nil)
	if err != nil {
		diags.AddError(fmt.Sprintf("Failed to read %s", r.entity), fmt.Sprintf("name_get failed: %s", err))
		return
	}
	var name string
	if err := json.Unmarshal(v, &name); err != nil {
		diags.AddError("Failed to parse name", err.Error())
		return
	}

	// Read maintenance mode.
	mmRaw, err := r.client.MakeRequest(ctx, apiPath, "maintenance_mode_get", nil)
	if err != nil {
		diags.AddError("Failed to read maintenance mode", fmt.Sprintf("maintenance_mode_get failed: %s", err))
		return
	}
	var mm maintenanceModeResult
	if err := json.Unmarshal(mmRaw, &mm); err != nil {
		diags.AddError("Failed to parse maintenance mode", err.Error())
		return
	}
	if mm.Until != nil {
		diags.Append(state.SetAttribute(ctx, path.Root("maintenance_until"), types.Int64Value(*mm.Until))...)
	} else {
		diags.Append(state.SetAttribute(ctx, path.Root("maintenance_until"), types.Int64Null())...)
	}

	// For service: read status. If API returns a transient value like "pending",
	// preserve the previous state value.
	if r.entity == entityService {
		statusRaw, err := r.client.MakeRequest(ctx, apiPath, "status_get", nil)
		if err != nil {
			diags.AddError("Failed to read service status", fmt.Sprintf("status_get failed: %s", err))
			return
		}
		var status string
		if err := json.Unmarshal(statusRaw, &status); err != nil {
			diags.AddError("Failed to parse service status", err.Error())
			return
		}
		if status == "online" || status == "offline" {
			diags.Append(state.SetAttribute(ctx, path.Root("status"), types.StringValue(status))...)
		}
		tflog.Debug(ctx, fmt.Sprintf("Read service %d status: %s", entityID, status))
	}

	diags.Append(state.SetAttribute(ctx, path.Root("id"), types.Int64Value(entityID))...)
	diags.Append(state.SetAttribute(ctx, path.Root("name"), types.StringValue(name))...)

	tflog.Debug(ctx, fmt.Sprintf("Read %s %d: name=%s", r.entity, entityID, name))
}

// readIPs reads service upstream IPs from the API.
func (r *EntityResource) readIPs(ctx context.Context, serviceID int64) ([]string, error) {
	apiPath := r.entity.apiPath(serviceID)

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

// reconcileIPs preserves state ordering for IPs that still exist in the API
// and appends any new API IPs at the end.
func reconcileIPs(stateIPs, apiIPs []string) []string {
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

	return reconciled
}
