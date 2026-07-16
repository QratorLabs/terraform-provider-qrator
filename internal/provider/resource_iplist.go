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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

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
	_ resource.Resource                 = &IPListResource{}
	_ resource.ResourceWithImportState  = &IPListResource{}
	_ resource.ResourceWithUpgradeState = &IPListResource{}
)

type IPListResource struct {
	client client.QratorClientAPI
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
	attrs := map[string]schema.Attribute{
		r.entity.idField(): schema.Int64Attribute{
			Description: fmt.Sprintf("The %s ID.", r.entity),
			Required:    true,
			PlanModifiers: []planmodifier.Int64{
				int64planmodifier.RequiresReplace(),
			},
		},
		"entries": schema.MapNestedAttribute{
			Description: fmt.Sprintf("IP entries in the %s. Each key is an IP address.", r.kind),
			Required:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
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
	}

	attrs["exclusive"] = schema.BoolAttribute{
		Description: "When true (default), removes any IP not present in entries (including UI-added). When false, only entries defined here are managed; externally added IPs are left untouched.",
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(true),
	}

	if r.kind == ipListWhitelist {
		attrs["default_drop"] = schema.BoolAttribute{
			Description: "Drop traffic from non-whitelisted IPs. When true, only whitelisted IPs are allowed.",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		}
	}

	resp.Schema = schema.Schema{
		Version:     1,
		Description: fmt.Sprintf("Manages the %s for a %s in Qrator.", r.kind, r.entity),
		Attributes:  attrs,
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
	var entries map[string]IPListEntryValueModel
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("entries"), &entries)...)
	var exclusive types.Bool
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("exclusive"), &exclusive)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planned := entries
	r.syncEntries(ctx, entityID.ValueInt64(), nil, planned, exclusive.ValueBool(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	entries, err := r.readAndReconcile(ctx, entityID.ValueInt64(), planned, exclusive.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read entries after create", err.Error())
		return
	}
	fillMissingFromDesired(entries, planned)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(r.entity.idField()), entityID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("entries"), entries)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("exclusive"), exclusive)...)

	if r.kind == ipListWhitelist {
		var defaultDrop types.Bool
		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("default_drop"), &defaultDrop)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if defaultDrop.ValueBool() {
			apiPath := r.entity.apiPath(entityID.ValueInt64())
			if _, err := r.client.MakeRequest(ctx, apiPath, "not_whitelisted_policy_set", []interface{}{"drop"}); err != nil {
				resp.Diagnostics.AddError("Failed to set default_drop", err.Error())
				return
			}
		}
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("default_drop"), defaultDrop)...)
	}
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *IPListResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var entityID types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root(r.entity.idField()), &entityID)...)
	var stateEntries map[string]IPListEntryValueModel
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("entries"), &stateEntries)...)
	var exclusive types.Bool
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("exclusive"), &exclusive)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// After import, exclusive is null (only entity ID is set by ImportState).
	// Default to true to match the schema default and avoid returning an empty
	// entries map from readAndReconcile in non-exclusive mode.
	if exclusive.IsNull() {
		exclusive = types.BoolValue(true)
	}

	entries, err := r.readAndReconcile(ctx, entityID.ValueInt64(), stateEntries, exclusive.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read entries", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(r.entity.idField()), entityID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("entries"), entries)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("exclusive"), exclusive)...)

	if r.kind == ipListWhitelist {
		apiPath := r.entity.apiPath(entityID.ValueInt64())
		canRead := true
		if r.entity == entityService {
			statusRaw, err := r.client.MakeRequest(ctx, apiPath, "status_get", nil)
			if err == nil {
				var status string
				json.Unmarshal(statusRaw, &status)
				canRead = (status == "online")
			}
		}
		if canRead {
			policyRaw, err := r.client.MakeRequest(ctx, apiPath, "not_whitelisted_policy_get", nil)
			if err != nil {
				resp.Diagnostics.AddError("Failed to read default_drop", fmt.Sprintf("not_whitelisted_policy_get failed: %s", err))
				return
			}
			var policy string
			if err := json.Unmarshal(policyRaw, &policy); err != nil {
				resp.Diagnostics.AddError("Failed to parse default_drop", err.Error())
				return
			}
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("default_drop"), types.BoolValue(policy == "drop"))...)
		}
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *IPListResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var entityID types.Int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root(r.entity.idField()), &entityID)...)
	var stateEntries map[string]IPListEntryValueModel
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("entries"), &stateEntries)...)
	var entries map[string]IPListEntryValueModel
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("entries"), &entries)...)
	var exclusive types.Bool
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("exclusive"), &exclusive)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planned := entries
	r.syncEntries(ctx, entityID.ValueInt64(), stateEntries, planned, exclusive.ValueBool(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	entries, err := r.readAndReconcile(ctx, entityID.ValueInt64(), planned, exclusive.ValueBool())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read entries after update", err.Error())
		return
	}
	fillMissingFromDesired(entries, planned)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(r.entity.idField()), entityID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("entries"), entries)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("exclusive"), exclusive)...)

	if r.kind == ipListWhitelist {
		var planDrop, stateDrop types.Bool
		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("default_drop"), &planDrop)...)
		resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("default_drop"), &stateDrop)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if planDrop.ValueBool() != stateDrop.ValueBool() {
			apiPath := r.entity.apiPath(entityID.ValueInt64())
			apiVal := "accept"
			if planDrop.ValueBool() {
				apiVal = "drop"
			}
			if _, err := r.client.MakeRequest(ctx, apiPath, "not_whitelisted_policy_set", []interface{}{apiVal}); err != nil {
				resp.Diagnostics.AddError("Failed to set default_drop", err.Error())
				return
			}
		}
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("default_drop"), planDrop)...)
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func (r *IPListResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var entityID types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root(r.entity.idField()), &entityID)...)
	var exclusive types.Bool
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("exclusive"), &exclusive)...)
	var stateEntries map[string]IPListEntryValueModel
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("entries"), &stateEntries)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := r.entity.apiPath(entityID.ValueInt64())

	if exclusive.IsNull() || exclusive.ValueBool() {
		// Exclusive mode: TF owns the entire list — flush everything.
		if r.kind == ipListWhitelist {
			if _, err := r.client.MakeRequest(ctx, apiPath, "not_whitelisted_policy_set", []interface{}{"accept"}); err != nil {
				tflog.Warn(ctx, fmt.Sprintf("Failed to reset not_whitelisted_policy: %s", err))
			}
		}
		if _, err := r.client.MakeRequest(ctx, apiPath, r.kind.methodFlush(), nil); err != nil {
			resp.Diagnostics.AddError("Failed to flush entries", err.Error())
		}
	} else {
		// Additive mode: only remove the IPs that Terraform was managing.
		ips := make([]string, 0, len(stateEntries))
		for ip := range stateEntries {
			ips = append(ips, ip)
		}
		if len(ips) > 0 {
			if _, err := r.client.MakeRequest(ctx, apiPath, r.kind.methodRemove(), ips); err != nil {
				resp.Diagnostics.AddError("Failed to remove entries", err.Error())
			}
		}
	}
}

func (r *IPListResource) syncEntries(ctx context.Context, entityID int64, prevEntries, desired map[string]IPListEntryValueModel, exclusive bool, diags *diag.Diagnostics) {
	apiPath := r.entity.apiPath(entityID)

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

	currentByIP := make(map[string]IPListEntryValueModel, len(current))
	for _, e := range current {
		currentByIP[e.IP.ValueString()] = IPListEntryValueModel{TTL: e.TTL, Comment: e.Comment}
	}

	var toRemove []string
	var toAdd []IPListEntryModel

	for ip := range currentByIP {
		_, inDesired := desired[ip]
		if inDesired {
			continue
		}
		if exclusive {
			toRemove = append(toRemove, ip)
		} else {
			if _, inPrev := prevEntries[ip]; inPrev {
				toRemove = append(toRemove, ip)
			}
		}
	}

	// Permanent entries (ttl=0) cannot be overwritten in-place; remove first.
	for ip, de := range desired {
		ce, exists := currentByIP[ip]
		if !exists {
			toAdd = append(toAdd, IPListEntryModel{IP: types.StringValue(ip), TTL: de.TTL, Comment: de.Comment})
		} else if !entryValueEqual(ce, de) {
			if ce.TTL.ValueInt64() == 0 {
				toRemove = append(toRemove, ip)
			}
			toAdd = append(toAdd, IPListEntryModel{IP: types.StringValue(ip), TTL: de.TTL, Comment: de.Comment})
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

func (r *IPListResource) readAndReconcile(ctx context.Context, entityID int64, desired map[string]IPListEntryValueModel, exclusive bool) (map[string]IPListEntryValueModel, error) {
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

	managed := make(map[string]IPListEntryValueModel, len(desired))
	for _, e := range apiEntries {
		ip := e.IP.ValueString()
		if exclusive {
			managed[ip] = IPListEntryValueModel{TTL: e.TTL, Comment: e.Comment}
		} else if _, ok := desired[ip]; ok {
			managed[ip] = IPListEntryValueModel{TTL: e.TTL, Comment: e.Comment}
		}
	}

	tflog.Debug(ctx, fmt.Sprintf("Read %s %d %s: %d managed entries (API total: %d)", r.entity, entityID, r.kind, len(managed), len(apiEntries)))
	return managed, nil
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

// fillMissingFromDesired ensures every desired entry is present in result.
// If readAndReconcile didn't return an entry we just synced (API propagation
// delay or race), fall back to the desired values so Terraform doesn't report
// "element has vanished". The next Read will correct any remaining discrepancy.
func fillMissingFromDesired(result, desired map[string]IPListEntryValueModel) {
	for ip, de := range desired {
		if _, ok := result[ip]; !ok {
			result[ip] = de
		}
	}
}

func entryValueEqual(a, b IPListEntryValueModel) bool {
	return a.TTL.ValueInt64() == b.TTL.ValueInt64() &&
		a.Comment.ValueString() == b.Comment.ValueString()
}

// ---------------------------------------------------------------------------
// State upgrade v0 → v1: entries Set{ip,ttl,comment} → Map[ip]{ttl,comment}
// ---------------------------------------------------------------------------

// v0 state structs — one per entity×kind combination.

type ipListV0DomainWhitelist struct {
	DomainID    types.Int64        `tfsdk:"domain_id"`
	Entries     []IPListEntryModel `tfsdk:"entries"`
	DefaultDrop types.Bool         `tfsdk:"default_drop"`
}

type ipListV0DomainBlacklist struct {
	DomainID types.Int64        `tfsdk:"domain_id"`
	Entries  []IPListEntryModel `tfsdk:"entries"`
}

type ipListV0ServiceWhitelist struct {
	ServiceID   types.Int64        `tfsdk:"service_id"`
	Entries     []IPListEntryModel `tfsdk:"entries"`
	DefaultDrop types.Bool         `tfsdk:"default_drop"`
}

type ipListV0ServiceBlacklist struct {
	ServiceID types.Int64        `tfsdk:"service_id"`
	Entries   []IPListEntryModel `tfsdk:"entries"`
}

// v1 state structs — used only in the upgrader to drive resp.State.Set.

type ipListV1DomainWhitelist struct {
	DomainID    types.Int64                     `tfsdk:"domain_id"`
	Entries     map[string]IPListEntryValueModel `tfsdk:"entries"`
	Exclusive   types.Bool                      `tfsdk:"exclusive"`
	DefaultDrop types.Bool                      `tfsdk:"default_drop"`
}

type ipListV1DomainBlacklist struct {
	DomainID  types.Int64                     `tfsdk:"domain_id"`
	Entries   map[string]IPListEntryValueModel `tfsdk:"entries"`
	Exclusive types.Bool                      `tfsdk:"exclusive"`
}

type ipListV1ServiceWhitelist struct {
	ServiceID   types.Int64                     `tfsdk:"service_id"`
	Entries     map[string]IPListEntryValueModel `tfsdk:"entries"`
	Exclusive   types.Bool                      `tfsdk:"exclusive"`
	DefaultDrop types.Bool                      `tfsdk:"default_drop"`
}

type ipListV1ServiceBlacklist struct {
	ServiceID types.Int64                     `tfsdk:"service_id"`
	Entries   map[string]IPListEntryValueModel `tfsdk:"entries"`
	Exclusive types.Bool                      `tfsdk:"exclusive"`
}

func (r *IPListResource) UpgradeState(_ context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{
		0: {
			PriorSchema:   r.schemaV0(),
			StateUpgrader: r.upgradeV0,
		},
	}
}

func (r *IPListResource) schemaV0() *schema.Schema {
	attrs := map[string]schema.Attribute{
		r.entity.idField(): schema.Int64Attribute{
			Required: true,
			PlanModifiers: []planmodifier.Int64{
				int64planmodifier.RequiresReplace(),
			},
		},
		"entries": schema.SetNestedAttribute{
			Required: true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"ip":      schema.StringAttribute{Required: true},
					"ttl":     schema.Int64Attribute{Optional: true, Computed: true},
					"comment": schema.StringAttribute{Optional: true, Computed: true},
				},
			},
		},
	}
	if r.kind == ipListWhitelist {
		attrs["default_drop"] = schema.BoolAttribute{Optional: true, Computed: true}
	}
	return &schema.Schema{Attributes: attrs}
}

func oldEntriesToMap(entries []IPListEntryModel) map[string]IPListEntryValueModel {
	m := make(map[string]IPListEntryValueModel, len(entries))
	for _, e := range entries {
		m[e.IP.ValueString()] = IPListEntryValueModel{TTL: e.TTL, Comment: e.Comment}
	}
	return m
}

func (r *IPListResource) upgradeV0(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	switch {
	case r.entity == entityDomain && r.kind == ipListWhitelist:
		var old ipListV0DomainWhitelist
		resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &ipListV1DomainWhitelist{
			DomainID:    old.DomainID,
			Entries:     oldEntriesToMap(old.Entries),
			Exclusive:   types.BoolValue(true),
			DefaultDrop: old.DefaultDrop,
		})...)

	case r.entity == entityDomain && r.kind == ipListBlacklist:
		var old ipListV0DomainBlacklist
		resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &ipListV1DomainBlacklist{
			DomainID:  old.DomainID,
			Entries:   oldEntriesToMap(old.Entries),
			Exclusive: types.BoolValue(true),
		})...)

	case r.entity == entityService && r.kind == ipListWhitelist:
		var old ipListV0ServiceWhitelist
		resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &ipListV1ServiceWhitelist{
			ServiceID:   old.ServiceID,
			Entries:     oldEntriesToMap(old.Entries),
			Exclusive:   types.BoolValue(true),
			DefaultDrop: old.DefaultDrop,
		})...)

	case r.entity == entityService && r.kind == ipListBlacklist:
		var old ipListV0ServiceBlacklist
		resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &ipListV1ServiceBlacklist{
			ServiceID: old.ServiceID,
			Entries:   oldEntriesToMap(old.Entries),
			Exclusive: types.BoolValue(true),
		})...)
	}
}
