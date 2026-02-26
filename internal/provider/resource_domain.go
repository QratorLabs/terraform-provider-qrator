package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

var (
	_ resource.Resource                = &DomainResource{}
	_ resource.ResourceWithImportState = &DomainResource{}
)

type DomainResource struct {
	client *client.QratorClient
}

func NewDomainResource() resource.Resource {
	return &DomainResource{}
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func (r *DomainResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_domain"
}

func (r *DomainResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a domain name in Qrator.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "The domain ID.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The domain name.",
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
		},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func (r *DomainResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *DomainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected numeric domain ID")
		return
	}
	resp.State.SetAttribute(ctx, path.Root("id"), id)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func (r *DomainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan DomainModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := plan.ID.ValueInt64()
	apiPath := fmt.Sprintf("/request/domain/%d", domainID)

	if !plan.Name.IsNull() && !plan.Name.IsUnknown() {
		if _, err := r.client.MakeRequest(ctx, apiPath, "name_set", plan.Name.ValueString()); err != nil {
			resp.Diagnostics.AddError("Failed to set domain name", err.Error())
			return
		}
	}

	if !plan.NotWhitelistedPolicy.IsNull() && !plan.NotWhitelistedPolicy.IsUnknown() {
		if _, err := r.client.MakeRequest(ctx, apiPath, "not_whitelisted_policy_set", []interface{}{plan.NotWhitelistedPolicy.ValueString()}); err != nil {
			resp.Diagnostics.AddError("Failed to set not_whitelisted_policy", err.Error())
			return
		}
	}

	if err := r.readAndPopulate(ctx, domainID, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to read domain after create", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *DomainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state DomainModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readAndPopulate(ctx, state.ID.ValueInt64(), &state); err != nil {
		resp.Diagnostics.AddError("Failed to read domain", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *DomainResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state DomainModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := plan.ID.ValueInt64()
	apiPath := fmt.Sprintf("/request/domain/%d", domainID)

	if !plan.Name.IsNull() && !plan.Name.IsUnknown() &&
		(state.Name.IsNull() || plan.Name.ValueString() != state.Name.ValueString()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "name_set", plan.Name.ValueString()); err != nil {
			resp.Diagnostics.AddError("Failed to set domain name", err.Error())
			return
		}
	}

	if !plan.NotWhitelistedPolicy.IsNull() && !plan.NotWhitelistedPolicy.IsUnknown() &&
		(state.NotWhitelistedPolicy.IsNull() || plan.NotWhitelistedPolicy.ValueString() != state.NotWhitelistedPolicy.ValueString()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "not_whitelisted_policy_set", []interface{}{plan.NotWhitelistedPolicy.ValueString()}); err != nil {
			resp.Diagnostics.AddError("Failed to set not_whitelisted_policy", err.Error())
			return
		}
	}

	if err := r.readAndPopulate(ctx, domainID, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to read domain after update", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// ---------------------------------------------------------------------------
// Delete — no-op (domain is not deleted)
// ---------------------------------------------------------------------------

func (r *DomainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *DomainResource) readAndPopulate(ctx context.Context, domainID int64, model *DomainModel) error {
	apiPath := fmt.Sprintf("/request/domain/%d", domainID)

	v, err := r.client.MakeRequest(ctx, apiPath, "name_get", nil)
	if err != nil {
		return fmt.Errorf("name_get failed: %w", err)
	}

	var name string
	if err := json.Unmarshal(v, &name); err != nil {
		return fmt.Errorf("failed to parse name response: %w", err)
	}

	policyRaw, err := r.client.MakeRequest(ctx, apiPath, "not_whitelisted_policy_get", nil)
	if err != nil {
		return fmt.Errorf("not_whitelisted_policy_get failed: %w", err)
	}

	var policy string
	if err := json.Unmarshal(policyRaw, &policy); err != nil {
		return fmt.Errorf("failed to parse policy response: %w", err)
	}

	model.ID = types.Int64Value(domainID)
	model.Name = types.StringValue(name)
	model.NotWhitelistedPolicy = types.StringValue(policy)

	tflog.Debug(ctx, fmt.Sprintf("Read domain %d: name=%s policy=%s", domainID, name, policy))
	return nil
}
