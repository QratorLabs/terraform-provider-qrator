package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

// ---------------------------------------------------------------------------
// Generic IP list resource (whitelist / blacklist) for domain or service
// ---------------------------------------------------------------------------

type ipListKind string

const (
	ipListWhitelist ipListKind = "whitelist"
	ipListBlacklist ipListKind = "blacklist"
)

func (k ipListKind) methodAppend() string { return string(k) + "_append" }
func (k ipListKind) methodRemove() string { return string(k) + "_remove" }
func (k ipListKind) methodGet() string    { return string(k) + "_get" }
func (k ipListKind) methodFlush() string  { return string(k) + "_flush" }

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

func NewDomainWhitelistResource() resource.Resource {
	return &IPListResource{entity: entityDomain, kind: ipListWhitelist}
}

func NewDomainBlacklistResource() resource.Resource {
	return &IPListResource{entity: entityDomain, kind: ipListBlacklist}
}

func NewServiceWhitelistResource() resource.Resource {
	return &IPListResource{entity: entityService, kind: ipListWhitelist}
}

func NewServiceBlacklistResource() resource.Resource {
	return &IPListResource{entity: entityService, kind: ipListBlacklist}
}

// ---------------------------------------------------------------------------
// Resource struct
// ---------------------------------------------------------------------------

var (
	_ resource.Resource                   = &IPListResource{}
	_ resource.ResourceWithImportState    = &IPListResource{}
	_ resource.ResourceWithValidateConfig = &IPListResource{}
)

type IPListResource struct {
	client *client.QratorClient
	entity entityKind
	kind   ipListKind
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func (r *IPListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.entity.String() + "_" + string(r.kind)
}

func (r *IPListResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: fmt.Sprintf("Manages the %s for a %s in Qrator.", r.kind, r.entity),
		Attributes: map[string]schema.Attribute{
			r.entity.idField(): schema.Int64Attribute{
				Description: fmt.Sprintf("The %s ID.", r.entity),
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"entries": schema.ListNestedAttribute{
				Description: fmt.Sprintf("IP entries in the %s.", r.kind),
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"ip": schema.StringAttribute{
							Description: "IP address (e.g. 203.0.113.1).",
							Required:    true,
						},
						"ttl": schema.Int64Attribute{
							Description: "Time to live in seconds. 0 means permanent.",
							Optional:    true,
							Computed:    true,
							Default:     int64default.StaticInt64(0),
							Validators:  []validator.Int64{int64validator.AtLeast(0)},
						},
						"comment": schema.StringAttribute{
							Description: "Optional comment.",
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(""),
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

func (r *IPListResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *IPListResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var entries []IPListEntryModel
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("entries"), &entries)...)
	if resp.Diagnostics.HasError() {
		return
	}

	seen := make(map[string]bool)
	for i, e := range entries {
		if e.IP.IsUnknown() {
			continue
		}
		ip := e.IP.ValueString()
		if seen[ip] {
			resp.Diagnostics.AddAttributeError(path.Root("entries").AtListIndex(i),
				"Duplicate IP", fmt.Sprintf("Duplicate IP entry %q", ip))
		}
		seen[ip] = true
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func (r *IPListResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (r *IPListResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var entityID types.Int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root(r.entity.idField()), &entityID)...)
	var entries []IPListEntryModel
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("entries"), &entries)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.syncEntries(ctx, entityID.ValueInt64(), entries, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(r.entity.idField()), entityID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("entries"), entries)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *IPListResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var entityID types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root(r.entity.idField()), &entityID)...)
	var stateEntries []IPListEntryModel
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("entries"), &stateEntries)...)
	if resp.Diagnostics.HasError() {
		return
	}

	entries, err := r.readAndReconcile(ctx, entityID.ValueInt64(), stateEntries, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read entries", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(r.entity.idField()), entityID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("entries"), entries)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *IPListResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var entityID types.Int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root(r.entity.idField()), &entityID)...)
	var entries []IPListEntryModel
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("entries"), &entries)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.syncEntries(ctx, entityID.ValueInt64(), entries, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(r.entity.idField()), entityID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("entries"), entries)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func (r *IPListResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var entityID types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root(r.entity.idField()), &entityID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := r.entity.apiPath(entityID.ValueInt64())
	if _, err := r.client.MakeRequest(ctx, apiPath, r.kind.methodFlush(), nil); err != nil {
		resp.Diagnostics.AddError("Failed to flush entries", err.Error())
		return
	}
}

// ---------------------------------------------------------------------------
// syncEntries — read current API state, compute diff, apply changes
// ---------------------------------------------------------------------------

func (r *IPListResource) syncEntries(ctx context.Context, entityID int64, desired []IPListEntryModel, diags *diag.Diagnostics) {
	apiPath := r.entity.apiPath(entityID)

	// Read current API state.
	v, err := r.client.MakeRequest(ctx, apiPath, r.kind.methodGet(), []interface{}{"tuple"})
	if err != nil {
		diags.AddError("Failed to read current entries", err.Error())
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Raw %s response: %s", r.kind.methodGet(), string(v)))

	current, err := parseAPITuples(v)
	if err != nil {
		diags.AddError("Failed to parse API response", err.Error())
		return
	}

	// Build lookups by IP.
	currentByIP := make(map[string]*IPListEntryModel, len(current))
	for i := range current {
		currentByIP[current[i].IP.ValueString()] = &current[i]
	}
	desiredByIP := make(map[string]*IPListEntryModel, len(desired))
	for i := range desired {
		desiredByIP[desired[i].IP.ValueString()] = &desired[i]
	}

	// Entries in API but not desired, or changed → remove.
	var toRemove []string
	for ip, ce := range currentByIP {
		de, exists := desiredByIP[ip]
		if !exists || !ipEntryEqual(ce, de) {
			toRemove = append(toRemove, ip)
		}
	}

	// Entries desired but not in API, or changed → append.
	var toAdd []IPListEntryModel
	for ip, de := range desiredByIP {
		ce, exists := currentByIP[ip]
		if !exists || !ipEntryEqual(ce, de) {
			toAdd = append(toAdd, *de)
		}
	}

	tflog.Debug(ctx, fmt.Sprintf("Sync %s %d %s: %d to remove, %d to add", r.entity, entityID, r.kind, len(toRemove), len(toAdd)))

	if len(toRemove) > 0 {
		if _, err := r.client.MakeRequest(ctx, apiPath, r.kind.methodRemove(), toRemove); err != nil {
			diags.AddError("Failed to remove entries", err.Error())
			return
		}
	}

	if len(toAdd) > 0 {
		params := entriesToAPITuples(toAdd)
		if _, err := r.client.MakeRequest(ctx, apiPath, r.kind.methodAppend(), params); err != nil {
			diags.AddError("Failed to append entries", err.Error())
			return
		}
	}
}

// ---------------------------------------------------------------------------
// readAndReconcile — read API entries, reconcile with current state
// ---------------------------------------------------------------------------

func (r *IPListResource) readAndReconcile(ctx context.Context, entityID int64, stateEntries []IPListEntryModel, diags *diag.Diagnostics) ([]IPListEntryModel, error) {
	apiPath := r.entity.apiPath(entityID)

	v, err := r.client.MakeRequest(ctx, apiPath, r.kind.methodGet(), []interface{}{"tuple"})
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w", r.kind.methodGet(), err)
	}

	tflog.Debug(ctx, fmt.Sprintf("Raw %s response: %s", r.kind.methodGet(), string(v)))

	apiEntries, err := parseAPITuples(v)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s response: %w", r.kind.methodGet(), err)
	}

	// Index API entries by IP.
	apiByIP := make(map[string]IPListEntryModel, len(apiEntries))
	for _, e := range apiEntries {
		apiByIP[e.IP.ValueString()] = e
	}

	// Reconcile: preserve state ordering for entries that still exist in API,
	// update their values from API. Append any new API entries at the end.
	seen := make(map[string]bool, len(apiByIP))
	entries := make([]IPListEntryModel, 0, len(apiByIP))

	for _, se := range stateEntries {
		ip := se.IP.ValueString()
		if ae, ok := apiByIP[ip]; ok {
			entries = append(entries, ae)
			seen[ip] = true
		}
		// Entry removed from API → drop from state (drift detected).
	}

	// New entries in API not in current state.
	for ip, ae := range apiByIP {
		if !seen[ip] {
			entries = append(entries, ae)
		}
	}

	tflog.Debug(ctx, fmt.Sprintf("Read %s %d %s: %d entries (API: %d)", r.entity, entityID, r.kind, len(entries), len(apiEntries)))
	return entries, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseAPITuples(raw json.RawMessage) ([]IPListEntryModel, error) {
	var tuples [][]json.RawMessage
	if err := json.Unmarshal(raw, &tuples); err != nil {
		return nil, err
	}

	entries := make([]IPListEntryModel, 0, len(tuples))
	for _, t := range tuples {
		if len(t) < 1 {
			continue
		}
		var ip string
		if err := json.Unmarshal(t[0], &ip); err != nil {
			continue
		}

		var ttl int64
		if len(t) >= 2 {
			json.Unmarshal(t[1], &ttl)
		}

		var comment string
		if len(t) >= 3 {
			json.Unmarshal(t[2], &comment)
		}

		entries = append(entries, IPListEntryModel{
			IP:      types.StringValue(ip),
			TTL:     types.Int64Value(ttl),
			Comment: types.StringValue(comment),
		})
	}

	return entries, nil
}

func entriesToAPITuples(entries []IPListEntryModel) [][]interface{} {
	tuples := make([][]interface{}, len(entries))
	for i, e := range entries {
		tuples[i] = []interface{}{
			e.IP.ValueString(),
			e.TTL.ValueInt64(),
			e.Comment.ValueString(),
		}
	}
	return tuples
}

func ipEntryEqual(a, b *IPListEntryModel) bool {
	return a.IP.ValueString() == b.IP.ValueString() &&
		a.TTL.ValueInt64() == b.TTL.ValueInt64() &&
		a.Comment.ValueString() == b.Comment.ValueString()
}
