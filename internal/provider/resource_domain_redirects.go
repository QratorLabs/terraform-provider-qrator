package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

var (
	_ resource.Resource                   = &DomainRedirectsResource{}
	_ resource.ResourceWithImportState    = &DomainRedirectsResource{}
	_ resource.ResourceWithValidateConfig = &DomainRedirectsResource{}
)

// DomainRedirectsResource manages HTTP redirect rules for a domain.
type DomainRedirectsResource struct {
	client client.QratorClientAPI
}

func NewDomainRedirectsResource() resource.Resource {
	return &DomainRedirectsResource{}
}

// ---------------------------------------------------------------------------
// API types
// ---------------------------------------------------------------------------

type apiRedirectEntry struct {
	From     apiRedirectFrom    `json:"from"`
	Redirect *apiRedirectTarget `json:"redirect"` // null = disabled (blocks less specific rules)
}

type apiRedirectFrom struct {
	Port     int64               `json:"port"`
	Hostname apiRedirectHostname `json:"hostname"`
	URI      *apiRedirectURI     `json:"uri"` // null = any URI; no omitempty: must be sent even as null
}

type apiRedirectHostname struct {
	Type  string  `json:"type"`
	Value *string `json:"value,omitempty"` // only present for type="fqdn"
}

type apiRedirectURI struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type apiRedirectTarget struct {
	Code     int64   `json:"code"`
	Schema   *string `json:"schema,omitempty"` // optional; omit to keep the same schema
	Hostname *string `json:"hostname"`          // null = preserve request hostname; no omitempty
	Port     int64   `json:"port"`
	Path     *string `json:"path"` // null = preserve request path; no omitempty
	Args     bool    `json:"args"`
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func (r *DomainRedirectsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_domain_redirects"
}

func (r *DomainRedirectsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages HTTP redirect rules for a domain in Qrator. " +
			"Rules are evaluated in order; a null redirect target blocks matching by less-specific rules.",
		Attributes: map[string]schema.Attribute{
			"domain_id": schema.Int64Attribute{
				Description: "The domain ID.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"redirects": schema.ListNestedAttribute{
				Description: "List of redirect rules (max 70). Order is preserved.",
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"from": schema.SingleNestedAttribute{
							Description: "Criteria for matching incoming requests.",
							Required:    true,
							Attributes: map[string]schema.Attribute{
								"port": schema.Int64Attribute{
									Description: "Incoming port to match: 80 or 443.",
									Required:    true,
									Validators: []validator.Int64{
										int64validator.OneOf(80, 443),
									},
								},
								"hostname": schema.SingleNestedAttribute{
									Description: "Hostname matcher.",
									Required:    true,
									Attributes: map[string]schema.Attribute{
										"type": schema.StringAttribute{
											Description: `Hostname match type: "any" matches any hostname; ` +
												`"fqdn" matches a specific hostname (requires value).`,
											Required: true,
											Validators: []validator.String{
												stringvalidator.OneOf("any", "fqdn"),
											},
										},
										"value": schema.StringAttribute{
											Description: `Specific hostname. Required when type is "fqdn".`,
											Optional:    true,
										},
									},
								},
								"uri": schema.SingleNestedAttribute{
									Description: "URI path matcher. Omit (null) to match any URI.",
									Optional:    true,
									Attributes: map[string]schema.Attribute{
										"type": schema.StringAttribute{
											Description: `URI match type: "exact" (full path match), ` +
												`"stop" (prefix match, longer prefix wins), ` +
												`"subdir" (deprecated alias for "stop").`,
											Required: true,
											Validators: []validator.String{
												stringvalidator.OneOf("exact", "stop", "subdir"),
											},
										},
										"value": schema.StringAttribute{
											Description: "URI pattern (1-500 characters).",
											Required:    true,
										},
									},
								},
							},
						},
						"redirect": schema.SingleNestedAttribute{
							Description: "Redirect target. " +
								"Omit (null) to disable redirect for this rule, blocking less-specific rules.",
							Optional: true,
							Attributes: map[string]schema.Attribute{
								"code": schema.Int64Attribute{
									Description: "HTTP redirect response code: 301, 302, 307, or 308.",
									Required:    true,
									Validators: []validator.Int64{
										int64validator.OneOf(301, 302, 307, 308),
									},
								},
								"schema": schema.StringAttribute{
									Description: `Redirect schema: "http", "https", or custom (up to 10 chars). ` +
										"Omit to preserve the schema from the original request.",
									Optional: true,
								},
								"hostname": schema.StringAttribute{
									Description: "Redirect target hostname. " +
										"Omit (null) to preserve the hostname from the original request.",
									Optional: true,
								},
								"port": schema.Int64Attribute{
									Description: "Redirect target port (1-65535).",
									Required:    true,
									Validators: []validator.Int64{
										int64validator.Between(1, 65535),
									},
								},
								"path": schema.StringAttribute{
									Description: "Redirect target path. " +
										"Omit (null) to preserve the path from the original request.",
									Optional: true,
								},
								"args": schema.BoolAttribute{
									Description: "If true, preserve query string arguments. " +
										"If false, strip query arguments.",
									Required: true,
								},
							},
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

func (r *DomainRedirectsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *DomainRedirectsResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var model DomainRedirectsResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(model.Redirects) > 70 {
		resp.Diagnostics.AddAttributeError(path.Root("redirects"),
			"Too many redirect rules",
			fmt.Sprintf("Maximum 70 redirect rules allowed; got %d.", len(model.Redirects)))
		return
	}

	// Per-port counters for API constraints:
	//   "only one 'any' per port"     — at most one hostname.type="any" rule per port
	//   "only one 'default' per port" — at most one uri=null rule per port
	anyHostnamePerPort := make(map[int64]int)  // port → count of hostname=any rules
	defaultURIPerPort := make(map[int64]int)   // port → count of uri=null rules
	seen := make(map[string]bool, len(model.Redirects))

	for i := range model.Redirects {
		e := &model.Redirects[i]

		// hostname.type="fqdn" requires a non-empty value.
		// Skip if value is unknown (computed attribute — will be validated at apply time).
		if !e.From.Hostname.Type.IsNull() && !e.From.Hostname.Type.IsUnknown() &&
			e.From.Hostname.Type.ValueString() == "fqdn" &&
			!e.From.Hostname.Value.IsUnknown() {
			if e.From.Hostname.Value.IsNull() || e.From.Hostname.Value.ValueString() == "" {
				resp.Diagnostics.AddAttributeError(
					path.Root("redirects").AtListIndex(i).AtName("from").AtName("hostname").AtName("value"),
					"Missing hostname value",
					`hostname.value is required and must be non-empty when hostname.type is "fqdn".`)
			}
		}

		// Skip per-port and uniqueness checks when key components are unknown.
		if e.From.Port.IsUnknown() || e.From.Hostname.Type.IsUnknown() {
			continue
		}
		port := e.From.Port.ValueInt64()

		// "only one 'any' per port": at most one hostname.type="any" rule per port.
		if e.From.Hostname.Type.ValueString() == "any" {
			anyHostnamePerPort[port]++
			if anyHostnamePerPort[port] > 1 {
				resp.Diagnostics.AddAttributeError(
					path.Root("redirects").AtListIndex(i).AtName("from").AtName("hostname"),
					"Duplicate any-hostname rule",
					fmt.Sprintf("Only one rule with hostname.type=\"any\" is allowed per port. "+
						"Port %d already has an earlier any-hostname rule.", port))
			}
		}

		// "only one 'default' per port": at most one uri=null rule per port.
		if e.From.URI == nil {
			defaultURIPerPort[port]++
			if defaultURIPerPort[port] > 1 {
				resp.Diagnostics.AddAttributeError(
					path.Root("redirects").AtListIndex(i).AtName("from").AtName("uri"),
					"Duplicate default-URI rule",
					fmt.Sprintf("Only one rule with uri=null (match any URI) is allowed per port. "+
						"Port %d already has an earlier uri=null rule.", port))
			}
		}

		// Exact uniqueness check by composite key.
		key := redirectCompositeKey(e)
		if seen[key] {
			resp.Diagnostics.AddAttributeError(
				path.Root("redirects").AtListIndex(i).AtName("from"),
				"Duplicate redirect rule",
				fmt.Sprintf("A redirect rule with from=%s already exists at an earlier index.", key))
		}
		seen[key] = true
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func (r *DomainRedirectsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected a numeric domain ID.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("domain_id"), id)...)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func (r *DomainRedirectsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan DomainRedirectsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := entityDomain.apiPath(plan.DomainID.ValueInt64())
	if err := r.writeRedirects(ctx, apiPath, plan.Redirects); err != nil {
		resp.Diagnostics.AddError("Failed to set redirect rules", err.Error())
		return
	}

	newState, err := r.readRedirects(ctx, apiPath, plan.Redirects)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read redirect rules after create", err.Error())
		return
	}
	newState.DomainID = plan.DomainID

	resp.Diagnostics.Append(resp.State.Set(ctx, &newState)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *DomainRedirectsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state DomainRedirectsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := entityDomain.apiPath(state.DomainID.ValueInt64())
	newState, err := r.readRedirects(ctx, apiPath, state.Redirects)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read redirect rules", err.Error())
		return
	}
	newState.DomainID = state.DomainID

	resp.Diagnostics.Append(resp.State.Set(ctx, &newState)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *DomainRedirectsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan DomainRedirectsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := entityDomain.apiPath(plan.DomainID.ValueInt64())
	if err := r.writeRedirects(ctx, apiPath, plan.Redirects); err != nil {
		resp.Diagnostics.AddError("Failed to set redirect rules", err.Error())
		return
	}

	newState, err := r.readRedirects(ctx, apiPath, plan.Redirects)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read redirect rules after update", err.Error())
		return
	}
	newState.DomainID = plan.DomainID

	resp.Diagnostics.Append(resp.State.Set(ctx, &newState)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func (r *DomainRedirectsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state DomainRedirectsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// redirect_set([]) clears all redirect rules.
	apiPath := entityDomain.apiPath(state.DomainID.ValueInt64())
	if err := r.writeRedirects(ctx, apiPath, nil); err != nil {
		resp.Diagnostics.AddError("Failed to clear redirect rules", err.Error())
		return
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// writeRedirects calls redirect_set with the given redirect list.
// Pass nil to send an empty list (clear all rules).
func (r *DomainRedirectsResource) writeRedirects(ctx context.Context, apiPath string, redirects []DomainRedirectModel) error {
	entries := make([]apiRedirectEntry, 0, len(redirects))
	for _, m := range redirects {
		entries = append(entries, redirectModelToAPI(m))
	}

	if _, err := r.client.MakeRequest(ctx, apiPath, "redirect_set", entries); err != nil {
		return fmt.Errorf("redirect_set failed: %w", err)
	}
	return nil
}

// readRedirects calls redirect_get and returns the parsed model.
// ref is used to preserve insertion order (reorderByPlanOrder).
func (r *DomainRedirectsResource) readRedirects(ctx context.Context, apiPath string, ref []DomainRedirectModel) (DomainRedirectsResourceModel, error) {
	v, err := r.client.MakeRequest(ctx, apiPath, "redirect_get", nil)
	if err != nil {
		return DomainRedirectsResourceModel{}, fmt.Errorf("redirect_get failed: %w", err)
	}

	var entries []apiRedirectEntry
	if err := json.Unmarshal(v, &entries); err != nil {
		return DomainRedirectsResourceModel{}, fmt.Errorf("failed to parse redirect_get response: %w", err)
	}

	models := make([]DomainRedirectModel, len(entries))
	for i, e := range entries {
		models[i] = apiToRedirectModel(e)
	}

	if len(ref) > 0 && len(models) > 0 {
		models = reorderByPlanOrder(ref, models, redirectCompositeKey)
	}

	tflog.Debug(ctx, fmt.Sprintf("Read %d redirect rule(s)", len(models)))
	return DomainRedirectsResourceModel{Redirects: models}, nil
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

// redirectCompositeKey builds a stable string key from a redirect's "from" matcher.
// Used by reorderByPlanOrder to match plan entries against API response entries.
func redirectCompositeKey(m *DomainRedirectModel) string {
	hostnameVal := ""
	if !m.From.Hostname.Value.IsNull() && !m.From.Hostname.Value.IsUnknown() {
		hostnameVal = m.From.Hostname.Value.ValueString()
	}
	uriKey := "null"
	if m.From.URI != nil {
		uriKey = m.From.URI.Type.ValueString() + ":" + m.From.URI.Value.ValueString()
	}
	return fmt.Sprintf("%d|%s|%s|%s",
		m.From.Port.ValueInt64(),
		m.From.Hostname.Type.ValueString(),
		hostnameVal,
		uriKey)
}

// apiToRedirectModel converts an API entry to a Terraform model.
func apiToRedirectModel(e apiRedirectEntry) DomainRedirectModel {
	m := DomainRedirectModel{}

	// from.port
	m.From.Port = types.Int64Value(e.From.Port)

	// from.hostname
	m.From.Hostname.Type = types.StringValue(e.From.Hostname.Type)
	if e.From.Hostname.Value != nil {
		m.From.Hostname.Value = types.StringValue(*e.From.Hostname.Value)
	} else {
		m.From.Hostname.Value = types.StringNull()
	}

	// from.uri (nil → null in Terraform)
	if e.From.URI != nil {
		m.From.URI = &DomainRedirectURIModel{
			Type:  types.StringValue(e.From.URI.Type),
			Value: types.StringValue(e.From.URI.Value),
		}
	}

	// redirect (nil → null in Terraform)
	if e.Redirect != nil {
		t := &DomainRedirectTargetModel{
			Code: types.Int64Value(e.Redirect.Code),
			Port: types.Int64Value(e.Redirect.Port),
			Args: types.BoolValue(e.Redirect.Args),
		}
		if e.Redirect.Schema != nil {
			t.Schema = types.StringValue(*e.Redirect.Schema)
		} else {
			t.Schema = types.StringNull()
		}
		if e.Redirect.Hostname != nil {
			t.Hostname = types.StringValue(*e.Redirect.Hostname)
		} else {
			t.Hostname = types.StringNull()
		}
		if e.Redirect.Path != nil {
			t.Path = types.StringValue(*e.Redirect.Path)
		} else {
			t.Path = types.StringNull()
		}
		m.Redirect = t
	}

	return m
}

// redirectModelToAPI converts a Terraform model to an API entry.
func redirectModelToAPI(m DomainRedirectModel) apiRedirectEntry {
	e := apiRedirectEntry{}

	// from
	e.From.Port = m.From.Port.ValueInt64()
	e.From.Hostname.Type = m.From.Hostname.Type.ValueString()
	if !m.From.Hostname.Value.IsNull() && !m.From.Hostname.Value.IsUnknown() {
		v := m.From.Hostname.Value.ValueString()
		e.From.Hostname.Value = &v
	}
	// from.uri: nil pointer → serialized as "uri": null (no omitempty on field)
	if m.From.URI != nil {
		e.From.URI = &apiRedirectURI{
			Type:  m.From.URI.Type.ValueString(),
			Value: m.From.URI.Value.ValueString(),
		}
	}

	// redirect: nil pointer → serialized as "redirect": null (no omitempty on field)
	if m.Redirect != nil {
		target := &apiRedirectTarget{
			Code: m.Redirect.Code.ValueInt64(),
			Port: m.Redirect.Port.ValueInt64(),
			Args: m.Redirect.Args.ValueBool(),
		}
		// schema: omitted if not set (optional field in API schema)
		if !m.Redirect.Schema.IsNull() && !m.Redirect.Schema.IsUnknown() {
			s := m.Redirect.Schema.ValueString()
			target.Schema = &s
		}
		// hostname: null if not set, else string value
		if !m.Redirect.Hostname.IsNull() && !m.Redirect.Hostname.IsUnknown() {
			h := m.Redirect.Hostname.ValueString()
			target.Hostname = &h
		}
		// path: null if not set, else string value
		if !m.Redirect.Path.IsNull() && !m.Redirect.Path.IsUnknown() {
			p := m.Redirect.Path.ValueString()
			target.Path = &p
		}
		e.Redirect = target
	}

	return e
}
