package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

var (
	_ resource.Resource                = &CDNSNIResource{}
	_ resource.ResourceWithImportState = &CDNSNIResource{}
)

type CDNSNIResource struct {
	client *client.QratorClient
}

func NewCDNSNIResource() resource.Resource {
	return &CDNSNIResource{}
}

type CDNSNIModel struct {
	DomainID types.Int64 `tfsdk:"domain_id"`
	Entries  types.List  `tfsdk:"entries"`
}

type cdnSNIEntry struct {
	Host        string `json:"host"`
	Certificate *int64 `json:"certificate"`
}

func (r *CDNSNIResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cdn_sni"
}

func (r *CDNSNIResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages SNI configuration for a CDN domain in Qrator.",
		Attributes: map[string]schema.Attribute{
			"domain_id": schema.Int64Attribute{
				Description: "The ID of the domain to manage CDN SNI for.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"entries": schema.ListNestedAttribute{
				Description: "List of hostname-to-certificate mappings.",
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"host": schema.StringAttribute{
							Description: "The CDN hostname.",
							Required:    true,
						},
						"certificate": schema.Int64Attribute{
							Description: "The certificate ID from storage, or null to disable TLS for this hostname.",
							Optional:    true,
						},
					},
				},
			},
		},
	}
}

func (r *CDNSNIResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *CDNSNIResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected numeric domain_id")
		return
	}
	resp.State.SetAttribute(ctx, path.Root("domain_id"), id)
}

func (r *CDNSNIResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CDNSNIModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := plan.DomainID.ValueInt64()
	apiPath := fmt.Sprintf("/request/cdn/%d", domainID)

	params, err := r.entriesToAPI(ctx, plan.Entries)
	if err != nil {
		resp.Diagnostics.AddError("Failed to parse SNI entries", err.Error())
		return
	}

	if _, err := r.client.MakeRequest(ctx, apiPath, "sni_set", params); err != nil {
		resp.Diagnostics.AddError("Failed to set CDN SNI", err.Error())
		return
	}

	r.readAndSetState(ctx, domainID, &resp.Diagnostics, &resp.State)
}

func (r *CDNSNIResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CDNSNIModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.readAndSetState(ctx, state.DomainID.ValueInt64(), &resp.Diagnostics, &resp.State)
}

func (r *CDNSNIResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CDNSNIModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := plan.DomainID.ValueInt64()
	apiPath := fmt.Sprintf("/request/cdn/%d", domainID)

	params, err := r.entriesToAPI(ctx, plan.Entries)
	if err != nil {
		resp.Diagnostics.AddError("Failed to parse SNI entries", err.Error())
		return
	}

	if _, err := r.client.MakeRequest(ctx, apiPath, "sni_set", params); err != nil {
		resp.Diagnostics.AddError("Failed to update CDN SNI", err.Error())
		return
	}

	r.readAndSetState(ctx, domainID, &resp.Diagnostics, &resp.State)
}

func (r *CDNSNIResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CDNSNIModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := fmt.Sprintf("/request/cdn/%d", state.DomainID.ValueInt64())
	if _, err := r.client.MakeRequest(ctx, apiPath, "sni_set", []interface{}{}); err != nil {
		resp.Diagnostics.AddError("Failed to clear CDN SNI", err.Error())
		return
	}
}

// entriesToAPI converts the Terraform list of SNI entries to API parameters.
func (r *CDNSNIResource) entriesToAPI(ctx context.Context, entries types.List) ([]map[string]interface{}, error) {
	var models []CDNSNIEntryModel
	if d := entries.ElementsAs(ctx, &models, false); d.HasError() {
		return nil, fmt.Errorf("failed to parse SNI entries")
	}

	params := make([]map[string]interface{}, len(models))
	for i, e := range models {
		entry := map[string]interface{}{
			"host": e.Host.ValueString(),
		}
		if e.Certificate.IsNull() {
			entry["certificate"] = nil
		} else {
			entry["certificate"] = e.Certificate.ValueInt64()
		}
		params[i] = entry
	}
	return params, nil
}

// readAndSetState reads SNI entries from the API and writes them into state.
func (r *CDNSNIResource) readAndSetState(ctx context.Context, domainID int64, diags *diag.Diagnostics, state *tfsdk.State) {
	apiPath := fmt.Sprintf("/request/cdn/%d", domainID)

	v, err := r.client.MakeRequest(ctx, apiPath, "sni_get", nil)
	if err != nil {
		diags.AddError("Failed to read CDN SNI", err.Error())
		return
	}

	var entries []cdnSNIEntry
	if err := json.Unmarshal(v, &entries); err != nil {
		diags.AddError("Failed to parse CDN SNI response", err.Error())
		return
	}

	sniAttrTypes := map[string]attr.Type{
		"host":        types.StringType,
		"certificate": types.Int64Type,
	}

	elems := make([]attr.Value, len(entries))
	for i, e := range entries {
		m := CDNSNIEntryModel{
			Host: types.StringValue(e.Host),
		}
		if e.Certificate != nil {
			m.Certificate = types.Int64Value(*e.Certificate)
		} else {
			m.Certificate = types.Int64Null()
		}
		obj, d := types.ObjectValueFrom(ctx, sniAttrTypes, m)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		elems[i] = obj
	}

	list, d := types.ListValue(types.ObjectType{AttrTypes: sniAttrTypes}, elems)
	diags.Append(d...)
	if diags.HasError() {
		return
	}

	diags.Append(state.SetAttribute(ctx, path.Root("domain_id"), types.Int64Value(domainID))...)
	diags.Append(state.SetAttribute(ctx, path.Root("entries"), list)...)

	tflog.Debug(ctx, fmt.Sprintf("Read CDN SNI for domain %d: %d entries", domainID, len(entries)))
}
