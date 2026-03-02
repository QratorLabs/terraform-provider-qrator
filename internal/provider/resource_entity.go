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
	_ resource.Resource                = &EntityResource{}
	_ resource.ResourceWithImportState = &EntityResource{}
)

// EntityResource manages a domain or service entity (name, policy).
type EntityResource struct {
	client *client.QratorClient
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
			Required:    true,
			PlanModifiers: []planmodifier.Int64{
				int64planmodifier.RequiresReplace(),
			},
		},
		"name": schema.StringAttribute{
			Description: fmt.Sprintf("The %s name.", r.entity),
			Optional:    true,
			Computed:    true,
		},
		"not_whitelisted_policy": schema.StringAttribute{
			Description: "Access policy for non-whitelisted IPs: accept or drop.",
			Optional:    true,
			Computed:    true,
			Default:     stringdefault.StaticString("accept"),
			Validators:  []validator.String{stringvalidator.OneOf("accept", "drop")},
		},
	}

	resp.Schema = schema.Schema{
		Description: fmt.Sprintf("Manages a %s in Qrator.", r.entity),
		Attributes:  attrs,
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
	var id types.Int64
	var name, policy types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("id"), &id)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("name"), &name)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("not_whitelisted_policy"), &policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	entityID := id.ValueInt64()
	apiPath := r.entity.apiPath(entityID)

	if !name.IsNull() && !name.IsUnknown() {
		if _, err := r.client.MakeRequest(ctx, apiPath, "name_set", name.ValueString()); err != nil {
			resp.Diagnostics.AddError(fmt.Sprintf("Failed to set %s name", r.entity), err.Error())
			return
		}
	}

	if !policy.IsNull() && !policy.IsUnknown() {
		if _, err := r.client.MakeRequest(ctx, apiPath, "not_whitelisted_policy_set", []interface{}{policy.ValueString()}); err != nil {
			resp.Diagnostics.AddError("Failed to set not_whitelisted_policy", err.Error())
			return
		}
	}

	r.readAndSetState(ctx, entityID, &resp.State, &resp.Diagnostics)
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

	r.readAndSetState(ctx, id.ValueInt64(), &resp.State, &resp.Diagnostics)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *EntityResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var id types.Int64
	var planName, planPolicy types.String
	var stateName, statePolicy types.String

	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("id"), &id)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("name"), &planName)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("not_whitelisted_policy"), &planPolicy)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("name"), &stateName)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("not_whitelisted_policy"), &statePolicy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	entityID := id.ValueInt64()
	apiPath := r.entity.apiPath(entityID)

	if !planName.IsNull() && !planName.IsUnknown() &&
		(stateName.IsNull() || planName.ValueString() != stateName.ValueString()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "name_set", planName.ValueString()); err != nil {
			resp.Diagnostics.AddError(fmt.Sprintf("Failed to set %s name", r.entity), err.Error())
			return
		}
	}

	if !planPolicy.IsNull() && !planPolicy.IsUnknown() &&
		(statePolicy.IsNull() || planPolicy.ValueString() != statePolicy.ValueString()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "not_whitelisted_policy_set", []interface{}{planPolicy.ValueString()}); err != nil {
			resp.Diagnostics.AddError("Failed to set not_whitelisted_policy", err.Error())
			return
		}
	}

	r.readAndSetState(ctx, entityID, &resp.State, &resp.Diagnostics)
}

// ---------------------------------------------------------------------------
// Delete — no-op (entity is not deleted)
// ---------------------------------------------------------------------------

func (r *EntityResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// readAndSetState reads all fields from the API and writes them into state.
func (r *EntityResource) readAndSetState(ctx context.Context, entityID int64, state *tfsdk.State, diags *diag.Diagnostics) {
	apiPath := r.entity.apiPath(entityID)

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

	policyRaw, err := r.client.MakeRequest(ctx, apiPath, "not_whitelisted_policy_get", nil)
	if err != nil {
		diags.AddError(fmt.Sprintf("Failed to read %s", r.entity), fmt.Sprintf("not_whitelisted_policy_get failed: %s", err))
		return
	}
	var policy string
	if err := json.Unmarshal(policyRaw, &policy); err != nil {
		diags.AddError("Failed to parse policy", err.Error())
		return
	}

	diags.Append(state.SetAttribute(ctx, path.Root("id"), types.Int64Value(entityID))...)
	diags.Append(state.SetAttribute(ctx, path.Root("name"), types.StringValue(name))...)
	diags.Append(state.SetAttribute(ctx, path.Root("not_whitelisted_policy"), types.StringValue(policy))...)

	tflog.Debug(ctx, fmt.Sprintf("Read %s %d: name=%s policy=%s", r.entity, entityID, name, policy))
}
