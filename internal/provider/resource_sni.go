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
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

var (
	_ resource.Resource                   = &SNIResource{}
	_ resource.ResourceWithImportState    = &SNIResource{}
	_ resource.ResourceWithValidateConfig = &SNIResource{}
)

// SNIResource manages SNI configuration for a domain or service.
type SNIResource struct {
	client *client.QratorClient
	entity entityKind
}

func NewDomainSNIResource() resource.Resource {
	return &SNIResource{entity: entityDomain}
}

func NewServiceSNIResource() resource.Resource {
	return &SNIResource{entity: entityService}
}

// ---------------------------------------------------------------------------
// API types
// ---------------------------------------------------------------------------

type sniAPIEntry struct {
	LinkID      int64   `json:"link_id"`
	Port        int64   `json:"port"`
	Hostname    *string `json:"hostname"`
	DomainID    int64   `json:"domain_id,omitempty"`
	Certificate int64   `json:"certificate"`
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func (r *SNIResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.entity.String() + "_sni"
}

func (r *SNIResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: fmt.Sprintf("Manages SNI configuration for a %s in Qrator.", r.entity),
		Attributes: map[string]schema.Attribute{
			r.entity.idField(): schema.Int64Attribute{
				Description: fmt.Sprintf("The %s ID.", r.entity),
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"links": schema.ListNestedAttribute{
				Description: "SNI entries. List of hostname-to-certificate mappings.",
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"link_id": schema.Int64Attribute{
							Description: "SNI link ID assigned by the API.",
							Computed:    true,
							PlanModifiers: []planmodifier.Int64{
								int64planmodifier.UseStateForUnknown(),
							},
						},
						"host": schema.StringAttribute{
							Description: "The hostname, or null for the default certificate.",
							Optional:    true,
						},
						"certificate": schema.Int64Attribute{
							Description: "The certificate ID from storage.",
							Required:    true,
						},
					},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func (r *SNIResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *SNIResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var links types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("links"), &links)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if links.IsNull() || links.IsUnknown() {
		return
	}

	var sniEntries []SNIEntryModel
	resp.Diagnostics.Append(links.ElementsAs(ctx, &sniEntries, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(sniEntries) > 1000 {
		resp.Diagnostics.AddAttributeError(path.Root("links"),
			"Too many SNI entries", "Maximum 1000 SNI entries allowed")
	}

	hasDefault := false
	hostnames := make(map[string]bool)
	for i, e := range sniEntries {
		if e.Host.IsNull() {
			if hasDefault {
				resp.Diagnostics.AddAttributeError(path.Root("links").AtListIndex(i),
					"Duplicate SNI entry", "Only one entry with null host (default certificate) is allowed")
			}
			hasDefault = true
		} else {
			h := e.Host.ValueString()
			if hostnames[h] {
				resp.Diagnostics.AddAttributeError(path.Root("links").AtListIndex(i),
					"Duplicate SNI entry", fmt.Sprintf("Duplicate hostname %q", h))
			}
			hostnames[h] = true
		}
	}

	if len(sniEntries) > 0 && !hasDefault {
		resp.Diagnostics.AddAttributeError(path.Root("links"),
			"Missing default SNI entry", "Non-empty SNI list must include an entry with null host (default certificate)")
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func (r *SNIResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", fmt.Sprintf("Expected numeric %s ID", r.entity))
		return
	}
	resp.State.SetAttribute(ctx, path.Root(r.entity.idField()), id)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func (r *SNIResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var entityID types.Int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root(r.entity.idField()), &entityID)...)
	var links types.List
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("links"), &links)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := entityID.ValueInt64()
	apiPath := r.entity.apiPath(id)

	var sniEntries []SNIEntryModel
	resp.Diagnostics.Append(links.ElementsAs(ctx, &sniEntries, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := r.writeSNI(ctx, apiPath, sniEntries); err != nil {
		resp.Diagnostics.AddError("Failed to set SNI", err.Error())
		return
	}

	newLinks, err := r.readSNILinks(ctx, id, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read SNI after create", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(r.entity.idField()), entityID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("links"), newLinks)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *SNIResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var entityID types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root(r.entity.idField()), &entityID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	links, err := r.readSNILinks(ctx, entityID.ValueInt64(), &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read SNI", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(r.entity.idField()), entityID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("links"), links)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *SNIResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var entityID types.Int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root(r.entity.idField()), &entityID)...)
	var planLinks types.List
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("links"), &planLinks)...)
	var stateLinks types.List
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("links"), &stateLinks)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := entityID.ValueInt64()
	apiPath := r.entity.apiPath(id)

	if err := r.updateSNI(ctx, apiPath, planLinks, stateLinks, &resp.Diagnostics); err != nil {
		return
	}

	links, err := r.readSNILinks(ctx, id, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read SNI after update", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(r.entity.idField()), entityID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("links"), links)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func (r *SNIResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var entityID types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root(r.entity.idField()), &entityID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := r.entity.apiPath(entityID.ValueInt64())
	if _, err := r.client.MakeRequest(ctx, apiPath, "sni_clear", nil); err != nil {
		resp.Diagnostics.AddError("Failed to clear SNI on delete", err.Error())
		return
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var sniAttrTypes = map[string]attr.Type{
	"link_id":     types.Int64Type,
	"host":        types.StringType,
	"certificate": types.Int64Type,
}

func sniObjType() types.ObjectType {
	return types.ObjectType{AttrTypes: sniAttrTypes}
}

// sniHostKey returns a string key for matching SNI entries by hostname.
// Null hostname (default certificate) maps to the empty string.
func sniHostKey(m *SNIEntryModel) string {
	if m.Host.IsNull() {
		return ""
	}
	return m.Host.ValueString()
}

func (r *SNIResource) readSNILinks(ctx context.Context, entityID int64, diags *diag.Diagnostics) (types.List, error) {
	apiPath := r.entity.apiPath(entityID)

	v, err := r.client.MakeRequest(ctx, apiPath, "sni_get", nil)
	if err != nil {
		return types.ListNull(sniObjType()), fmt.Errorf("sni_get failed: %w", err)
	}

	var sniEntries []sniAPIEntry
	if err := json.Unmarshal(v, &sniEntries); err != nil {
		return types.ListNull(sniObjType()), fmt.Errorf("failed to parse SNI response: %w", err)
	}

	tflog.Debug(ctx, fmt.Sprintf("Read %s %d SNI: %d entries", r.entity, entityID, len(sniEntries)))
	return entitySNIEntriesToList(ctx, sniEntries, diags), nil
}

// writeSNI replaces the full SNI state via sni_set. Used on Create.
func (r *SNIResource) writeSNI(ctx context.Context, apiPath string, entries []SNIEntryModel) ([]sniAPIEntry, error) {
	params := make([]map[string]interface{}, len(entries))
	for i, e := range entries {
		entry := map[string]interface{}{
			"port":        443,
			"certificate": e.Certificate.ValueInt64(),
		}
		if e.Host.IsNull() {
			entry["hostname"] = nil
		} else {
			entry["hostname"] = e.Host.ValueString()
		}
		params[i] = entry
	}

	result, err := r.client.MakeRequest(ctx, apiPath, "sni_set", params)
	if err != nil {
		return nil, fmt.Errorf("sni_set failed: %w", err)
	}

	var resp []sniAPIEntry
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse sni_set response: %w", err)
	}
	return resp, nil
}

// updateSNI performs an incremental SNI update using sni_link_add and
// sni_link_remove when state has link_ids.
func (r *SNIResource) updateSNI(ctx context.Context, apiPath string, plan, state types.List, diags *diag.Diagnostics) error {
	var planEntries, stateEntries []SNIEntryModel

	d := plan.ElementsAs(ctx, &planEntries, false)
	diags.Append(d...)
	if diags.HasError() {
		return fmt.Errorf("failed to parse plan SNI")
	}

	if !state.IsNull() && !state.IsUnknown() {
		d = state.ElementsAs(ctx, &stateEntries, false)
		diags.Append(d...)
		if diags.HasError() {
			return fmt.Errorf("failed to parse state SNI")
		}
	}

	// Build lookup: hostname → state entry (with link_id).
	stateByHost := make(map[string]*SNIEntryModel, len(stateEntries))
	for i := range stateEntries {
		stateByHost[sniHostKey(&stateEntries[i])] = &stateEntries[i]
	}

	// Build lookup: hostname → plan entry.
	planByHost := make(map[string]*SNIEntryModel, len(planEntries))
	for i := range planEntries {
		planByHost[sniHostKey(&planEntries[i])] = &planEntries[i]
	}

	// Compute diff.
	var toRemove []int64       // link_ids to remove
	var toAdd []SNIEntryModel  // entries to add/overwrite

	// Entries in state but not in plan → remove.
	for key, se := range stateByHost {
		if _, ok := planByHost[key]; !ok {
			if !se.LinkID.IsNull() && !se.LinkID.IsUnknown() {
				toRemove = append(toRemove, se.LinkID.ValueInt64())
			}
		}
	}

	// Entries in plan: add if new or certificate changed.
	for key, pe := range planByHost {
		se, exists := stateByHost[key]
		if !exists || se.Certificate.ValueInt64() != pe.Certificate.ValueInt64() {
			toAdd = append(toAdd, *pe)
		}
	}

	if len(toRemove) == 0 && len(toAdd) == 0 {
		return nil
	}

	// Remove old entries.
	for _, linkID := range toRemove {
		if _, err := r.client.MakeRequest(ctx, apiPath, "sni_link_remove", []interface{}{linkID}); err != nil {
			diags.AddError("Failed to remove SNI link", fmt.Sprintf("link_id %d: %s", linkID, err.Error()))
			return err
		}
	}

	// Add new/updated entries.
	for _, e := range toAdd {
		var hostname interface{}
		if e.Host.IsNull() {
			hostname = nil
		} else {
			hostname = e.Host.ValueString()
		}
		params := []interface{}{int64(443), e.Certificate.ValueInt64(), hostname}
		if _, err := r.client.MakeRequest(ctx, apiPath, "sni_link_add", params); err != nil {
			diags.AddError("Failed to add SNI link", err.Error())
			return err
		}
	}

	return nil
}

// entitySNIEntriesToList converts API SNI entries to a Terraform List value.
func entitySNIEntriesToList(ctx context.Context, entries []sniAPIEntry, diags *diag.Diagnostics) types.List {
	objType := sniObjType()

	models := make([]SNIEntryModel, len(entries))
	for i, e := range entries {
		models[i].LinkID = types.Int64Value(e.LinkID)
		if e.Hostname != nil {
			models[i].Host = types.StringValue(*e.Hostname)
		} else {
			models[i].Host = types.StringNull()
		}
		models[i].Certificate = types.Int64Value(e.Certificate)
	}

	elems := make([]attr.Value, len(models))
	for i, m := range models {
		obj, d := types.ObjectValueFrom(ctx, sniAttrTypes, m)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(objType)
		}
		elems[i] = obj
	}

	list, d := types.ListValue(objType, elems)
	diags.Append(d...)
	return list
}
