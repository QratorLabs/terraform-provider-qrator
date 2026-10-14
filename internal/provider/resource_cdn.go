package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
	"golang.org/x/sync/errgroup"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type CDNResource struct {
	client client.QratorClientAPI
}

func NewCDNResource() resource.Resource {
	return &CDNResource{}
}

func (r *CDNResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cdn"
}

func (r *CDNResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a CDN configuration for a domain in Qrator.",
		Version:     2,
		Attributes: map[string]schema.Attribute{
			"domain_id": schema.Int64Attribute{
				Description: "The ID of the domain to configure CDN for.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"access_control_allow_origin": schema.ListAttribute{
				Description: "List of origin regex patterns. If the Origin header from the client matches one of the patterns, CDN adds an Access-Control-Allow-Origin header equal to the received Origin value.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Validators:  []validator.List{listvalidator.UniqueValues()},
			},
			"cache_control": schema.StringAttribute{
				Description: `Controls cache TTL. "cdn" — CDN controls with default 6h; a number (7200–604800) — CDN controls with custom timeout in seconds; "origin" — origin Cache-Control/Expires headers are used.`,
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("cdn"),
			},
			"redirect_code": schema.Int64Attribute{
				Description: "HTTP-to-HTTPS redirect status code returned by CDN edge nodes. Must be 301, 302, 307, or 308. Leave unset to disable.",
				Optional:    true,
				Validators: []validator.Int64{
					int64validator.OneOf(301, 302, 307, 308),
				},
			},
			"cache_query_params": schema.SingleNestedAttribute{
				Description: `Controls which query parameters are included in the cache key. mode "ignore" excludes the listed params from the cache key (blacklist); mode "use" includes only the listed params (whitelist). With an empty params list, "ignore" means all params are used and "use" means all params are ignored. Default: {mode: "ignore", params: []}.`,
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"mode": schema.StringAttribute{
						Description: `"ignore" — exclude listed params from cache key. "use" — include only listed params.`,
						Required:    true,
						Validators: []validator.String{
							stringvalidator.OneOf("ignore", "use"),
						},
					},
					"params": schema.ListAttribute{
						Description: "Query parameter names. Up to 100 entries, each 1–255 URL-safe characters.",
						Required:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.UniqueValues(),
							listvalidator.SizeAtMost(100),
							listvalidator.ValueStringsAre(
								stringvalidator.LengthBetween(1, 255),
								stringvalidator.RegexMatches(
									cacheQueryParamNameRE,
									"must contain only URL-safe characters (alphanumeric, percent-encoded, or [-_.~])",
								),
							),
						},
					},
				},
			},
			"client_headers": schema.ListAttribute{
				Description: "Headers that will be added to every response sent by CDN to client. Format: header:value.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Validators:  []validator.List{listvalidator.UniqueValues()},
			},
			"client_ip_header": schema.StringAttribute{
				Description: "Header name containing the client IP address.",
				Optional:    true,
				Computed:    true,
			},
			"upstream_headers": schema.ListAttribute{
				Description: "Headers that will be added to every request sent by CDN to upstream. Format: header:value.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Validators:  []validator.List{listvalidator.UniqueValues()},
			},
			"access_filter": accessFilterSchemaAttribute(),
			"http2": schema.BoolAttribute{
				Description: "Enable CDN support for HTTP/2 (in addition to HTTP/1.1).",
				Optional:    true,
				Computed:    true,
			},
			"cache_errors": schema.ListNestedAttribute{
				Description: "Cache error responses from upstream. If upstream returns a matching status code, the next request for the same resource is delayed by the specified timeout (ms).",
				Optional:    true,
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"code": schema.Int64Attribute{
							Description: "HTTP status code from upstream to cache. Allowed values: 204, 305, 400, 403, 404, 414, 500, 501, 502, 503, 504.",
							Required:    true,
							Validators: []validator.Int64{
								int64validator.OneOf(204, 305, 400, 403, 404, 414, 500, 501, 502, 503, 504),
							},
						},
						"timeout": schema.Int64Attribute{
							Description: "Timeout in milliseconds before the next request is allowed (1000–300000).",
							Required:    true,
							Validators: []validator.Int64{
								int64validator.Between(1000, 300000),
							},
						},
					},
				},
			},
			"content_compression": contentCompressionSchemaAttribute(),
			"webp": schema.Int64Attribute{
				Description: "WebP image compression quality (0-100). When set, enables on-the-fly conversion of images to WebP format. Omit or set to null to disable.",
				Optional:    true,
				Computed:    true,
				Validators:  []validator.Int64{int64validator.Between(0, 100)},
			},
			"tls_versions": schema.ListAttribute{
				Description: `Allowed TLS protocol versions for CDN client connections. Valid values: "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3". At least one of TLSv1.2 or TLSv1.3 must be included.`,
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Validators: []validator.List{
					listvalidator.UniqueValues(),
					listvalidator.ValueStringsAre(
						stringvalidator.OneOf("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"),
					),
				},
			},
			"default_host": schema.StringAttribute{
				Description: "Default configured hostname returned by the API.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
	tflog.Debug(ctx, "Defined CDN resource schema")
}

func (r *CDNResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.QratorClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.QratorClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *CDNResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data CDNModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.TLSVersions.IsNull() || data.TLSVersions.IsUnknown() {
		return
	}

	var versions []string
	data.TLSVersions.ElementsAs(ctx, &versions, false)

	for _, v := range versions {
		if v == "TLSv1.2" || v == "TLSv1.3" {
			return
		}
	}
	resp.Diagnostics.AddAttributeError(
		path.Root("tls_versions"),
		"Invalid TLS versions",
		"At least one of TLSv1.2 or TLSv1.3 must be included.",
	)
}

func (r *CDNResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected numeric domain_id")
		return
	}
	resp.State.SetAttribute(ctx, path.Root("domain_id"), id)
}

func (r *CDNResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CDNModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := plan.DomainID.ValueInt64()
	apiPath := fmt.Sprintf("/request/cdn/%d", domainID)

	// CDN always exists in the API; Create applies the plan settings, then
	// reads back to populate computed fields (e.g. default_host).
	if !r.applyPlanToAPI(ctx, apiPath, plan, CDNModel{}, &resp.Diagnostics) {
		return
	}

	// plan.DefaultHost is unknown on first create — readCDNModel will fetch it.
	result, ok := r.readCDNModel(ctx, domainID, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &result)...)
}

func (r *CDNResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (r *CDNResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CDNModel
	var state CDNModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := plan.DomainID.ValueInt64()
	apiPath := fmt.Sprintf("/request/cdn/%d", domainID)

	if !r.applyPlanToAPI(ctx, apiPath, plan, state, &resp.Diagnostics) {
		return
	}

	// plan.DefaultHost is already known (UseStateForUnknown copies it from state).
	result, ok := r.readCDNModel(ctx, domainID, plan, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &result)...)
}

func (r *CDNResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CDNModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, ok := r.readCDNModel(ctx, state.DomainID.ValueInt64(), state, &resp.Diagnostics)
	if !ok {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &result)...)
}

// applyPlanToAPI sends changed plan settings to the CDN API.
// state is the prior state; pass CDNModel{} when creating.
// Returns false if any API call failed (diagnostics already set).
func (r *CDNResource) applyPlanToAPI(ctx context.Context, apiPath string, plan, state CDNModel, diags *diag.Diagnostics) bool {
	// access_control_allow_origin
	if !IsNullOrUnknown(plan.AccessControlAllowOrigin) &&
		ShouldUpdateList(plan.AccessControlAllowOrigin, state.AccessControlAllowOrigin, true) {
		var values []string
		plan.AccessControlAllowOrigin.ElementsAs(ctx, &values, false)
		if _, err := r.client.MakeRequest(ctx, apiPath, "access_control_allow_origin_set", values); err != nil {
			diags.AddError("Failed to update access_control_allow_origin", err.Error())
			return false
		}
	}

	// cache_control
	if !IsNullOrUnknown(plan.CacheControl) &&
		(state.CacheControl.IsNull() || plan.CacheControl.ValueString() != state.CacheControl.ValueString()) {
		param := cacheControlToAPI(plan.CacheControl.ValueString())
		if _, err := r.client.MakeRequest(ctx, apiPath, "cache_control_set", param); err != nil {
			diags.AddError("Failed to update cache_control", err.Error())
			return false
		}
	}

	// redirect_code
	if plan.RedirectCode.IsNull() {
		if !state.RedirectCode.IsNull() {
			if _, err := r.client.MakeRequest(ctx, apiPath, "redirect_set", nil); err != nil {
				diags.AddError("Failed to disable redirect", err.Error())
				return false
			}
		}
	} else if !plan.RedirectCode.IsUnknown() {
		if state.RedirectCode.IsNull() || plan.RedirectCode.ValueInt64() != state.RedirectCode.ValueInt64() {
			if _, err := r.client.MakeRequest(ctx, apiPath, "redirect_set", plan.RedirectCode.ValueInt64()); err != nil {
				diags.AddError("Failed to update redirect_code", err.Error())
				return false
			}
		}
	}

	// cache_query_params
	if !IsNullOrUnknown(plan.CacheQueryParams) {
		var planCQP CDNCacheQueryParamsModel
		plan.CacheQueryParams.As(ctx, &planCQP, basetypes.ObjectAsOptions{})

		shouldUpdate := IsNullOrUnknown(state.CacheQueryParams)
		if !shouldUpdate {
			var stateCQP CDNCacheQueryParamsModel
			state.CacheQueryParams.As(ctx, &stateCQP, basetypes.ObjectAsOptions{})
			shouldUpdate = planCQP.Mode.ValueString() != stateCQP.Mode.ValueString() ||
				!StringListsEqualIgnoreOrder(planCQP.Params, stateCQP.Params)
		}
		if shouldUpdate {
			var params []string
			planCQP.Params.ElementsAs(ctx, &params, false)
			if _, err := r.client.MakeRequest(ctx, apiPath, "cache_query_params_set", apiCacheQueryParams{
				Mode:   planCQP.Mode.ValueString(),
				Params: params,
			}); err != nil {
				diags.AddError("Failed to update cache_query_params", err.Error())
				return false
			}
		}
	}

	// client_headers
	if !IsNullOrUnknown(plan.ClientHeaders) &&
		ShouldUpdateList(plan.ClientHeaders, state.ClientHeaders, true) {
		var values []string
		plan.ClientHeaders.ElementsAs(ctx, &values, false)
		if _, err := r.client.MakeRequest(ctx, apiPath, "client_headers_set", values); err != nil {
			diags.AddError("Failed to update client_headers", err.Error())
			return false
		}
	}

	// client_ip_header
	if !IsNullOrUnknown(plan.ClientIPHeader) &&
		(state.ClientIPHeader.IsNull() || plan.ClientIPHeader.ValueString() != state.ClientIPHeader.ValueString()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "client_ip_header_set", plan.ClientIPHeader.ValueString()); err != nil {
			diags.AddError("Failed to update client_ip_header", err.Error())
			return false
		}
	}

	// upstream_headers
	if !IsNullOrUnknown(plan.UpstreamHeaders) &&
		ShouldUpdateList(plan.UpstreamHeaders, state.UpstreamHeaders, true) {
		var values []string
		plan.UpstreamHeaders.ElementsAs(ctx, &values, false)
		if _, err := r.client.MakeRequest(ctx, apiPath, "upstream_headers_set", values); err != nil {
			diags.AddError("Failed to update upstream_headers", err.Error())
			return false
		}
	}

	// http2
	if !IsNullOrUnknown(plan.HTTP2) &&
		(state.HTTP2.IsNull() || plan.HTTP2.ValueBool() != state.HTTP2.ValueBool()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "http2_set", plan.HTTP2.ValueBool()); err != nil {
			diags.AddError("Failed to update http2", err.Error())
			return false
		}
	}

	// cache_errors
	if !IsNullOrUnknown(plan.CacheErrors) {
		if err := r.updateCacheErrors(ctx, apiPath, "cache_errors_set", plan.CacheErrors, state.CacheErrors, diags); err != nil {
			return false
		}
	}

	// content_compression: sent only when configured and changed.
	if !IsNullOrUnknown(plan.ContentCompression) && !plan.ContentCompression.Equal(state.ContentCompression) {
		params, ok := contentCompressionToAPI(ctx, plan.ContentCompression, diags)
		if !ok {
			return false
		}
		if _, err := r.client.MakeRequest(ctx, apiPath, "content_compression_set", params); err != nil {
			diags.AddError("Failed to update content_compression", err.Error())
			return false
		}
	}

	// access_filter: filter_set replaces the whole filter, so it is sent only
	// when the attribute is configured and differs from the prior state.
	if !IsNullOrUnknown(plan.AccessFilter) && !plan.AccessFilter.Equal(state.AccessFilter) {
		m := accessFilterObjectToModel(ctx, plan.AccessFilter, diags)
		if diags.HasError() {
			return false
		}
		params, d := accessFilterToAPI(ctx, *m)
		diags.Append(d...)
		if diags.HasError() {
			return false
		}
		if _, err := r.client.MakeRequest(ctx, apiPath, "filter_set", params); err != nil {
			diags.AddError("Failed to update access_filter", err.Error())
			return false
		}
	}

	// webp
	if !IsNullOrUnknown(plan.WebP) &&
		(state.WebP.IsNull() || plan.WebP.ValueInt64() != state.WebP.ValueInt64()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "webp_set", plan.WebP.ValueInt64()); err != nil {
			diags.AddError("Failed to update webp", err.Error())
			return false
		}
	}

	// tls_versions
	if !IsNullOrUnknown(plan.TLSVersions) &&
		ShouldUpdateList(plan.TLSVersions, state.TLSVersions, true) {
		var values []string
		plan.TLSVersions.ElementsAs(ctx, &values, false)
		if _, err := r.client.MakeRequest(ctx, apiPath, "tls_versions_set", values); err != nil {
			diags.AddError("Failed to update tls_versions", err.Error())
			return false
		}
	}

	return true
}

// readCDNModel fetches all CDN settings from the API and returns a populated CDNModel.
// ref provides previously-known values: default_host is re-fetched only if unknown/null,
// and list fields are used to restore user-defined order after the API read.
func (r *CDNResource) readCDNModel(ctx context.Context, domainID int64, ref CDNModel, diags *diag.Diagnostics) (CDNModel, bool) {
	apiPath := fmt.Sprintf("/request/cdn/%d", domainID)

	var (
		accessControlAllowOrigin []string
		cacheControlRaw          json.RawMessage
		redirectCode             *int64
		cacheQueryParams         apiCacheQueryParams
		clientHeaders            []string
		clientIPHeader           *string
		webp                     int64
		upstreamHeaders          []string
		http2                    bool
		cacheErrors              []cdnCacheErrorEntry
		accessFilter             apiCdnFilter
		contentCompression       apiContentCompression
		tlsVersions              []string
		defaultHost              string
	)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "access_control_allow_origin_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &accessControlAllowOrigin)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "cache_control_get", nil)
		if err != nil {
			return err
		}
		cacheControlRaw = v
		return nil
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "cache_query_params_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &cacheQueryParams)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "redirect_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &redirectCode)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "client_headers_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &clientHeaders)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "client_ip_header_get", nil)
		if err != nil {
			return err
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return err
		}
		clientIPHeader = &s
		return nil
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "upstream_headers_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &upstreamHeaders)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "http2_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &http2)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "cache_errors_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &cacheErrors)
	})

	// content_compression, like access_filter, is read only when managed.
	manageCompression := !ref.ContentCompression.IsNull()
	if manageCompression {
		g.Go(func() error {
			v, err := r.client.MakeRequest(gctx, apiPath, "content_compression_get", nil)
			if err != nil {
				return err
			}
			return json.Unmarshal(v, &contentCompression)
		})
	}

	// access_filter is read only when managed (known or unknown in ref);
	// an unmanaged filter stays null in state.
	manageFilter := !ref.AccessFilter.IsNull()
	if manageFilter {
		g.Go(func() error {
			v, err := r.client.MakeRequest(gctx, apiPath, "filter_get", nil)
			if err != nil {
				return err
			}
			return json.Unmarshal(v, &accessFilter)
		})
	}

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "webp_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &webp)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "tls_versions_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &tlsVersions)
	})

	if ref.DefaultHost.IsUnknown() || ref.DefaultHost.IsNull() {
		g.Go(func() error {
			v, err := r.client.MakeRequest(gctx, apiPath, "default_host", nil)
			if err != nil {
				return err
			}
			return json.Unmarshal(v, &defaultHost)
		})
	}

	if err := g.Wait(); err != nil {
		diags.AddError("Failed to read CDN settings", err.Error())
		return CDNModel{}, false
	}

	// Parse ref lists for reordering API results to match user-defined order.
	var refACLO, refClientHeaders, refUpstreamHeaders, refTLSVersions []string
	var refCacheErrors []CDNCacheErrorEntryModel
	if !IsNullOrUnknown(ref.AccessControlAllowOrigin) {
		ref.AccessControlAllowOrigin.ElementsAs(ctx, &refACLO, false)
	}
	if !IsNullOrUnknown(ref.ClientHeaders) {
		ref.ClientHeaders.ElementsAs(ctx, &refClientHeaders, false)
	}
	if !IsNullOrUnknown(ref.UpstreamHeaders) {
		ref.UpstreamHeaders.ElementsAs(ctx, &refUpstreamHeaders, false)
	}
	if !IsNullOrUnknown(ref.TLSVersions) {
		ref.TLSVersions.ElementsAs(ctx, &refTLSVersions, false)
	}
	if !IsNullOrUnknown(ref.CacheErrors) {
		ref.CacheErrors.ElementsAs(ctx, &refCacheErrors, false)
	}

	strKey := func(s *string) string { return *s }
	ceKey := func(m *CDNCacheErrorEntryModel) string { return strconv.FormatInt(m.Code.ValueInt64(), 10) }

	var state CDNModel
	state.DomainID = types.Int64Value(domainID)

	aclO := reorderByPlanOrder(refACLO, accessControlAllowOrigin, strKey)
	state.AccessControlAllowOrigin, _ = types.ListValueFrom(ctx, types.StringType, aclO)
	state.AccessControlAllowOrigin, _ = NormalizeStringList(ctx, state.AccessControlAllowOrigin)

	cc, err := parseCacheControl(cacheControlRaw)
	if err != nil {
		diags.AddError("Failed to parse cache_control", err.Error())
		return CDNModel{}, false
	}
	state.CacheControl = types.StringValue(cc)
	if redirectCode == nil {
		state.RedirectCode = types.Int64Null()
	} else {
		state.RedirectCode = types.Int64Value(*redirectCode)
	}

	var refCQPParams []string
	if !IsNullOrUnknown(ref.CacheQueryParams) {
		var refCQP CDNCacheQueryParamsModel
		ref.CacheQueryParams.As(ctx, &refCQP, basetypes.ObjectAsOptions{})
		refCQP.Params.ElementsAs(ctx, &refCQPParams, false)
	}
	reorderedCQPParams := reorderByPlanOrder(refCQPParams, cacheQueryParams.Params, strKey)
	cqpParamsList, d := types.ListValueFrom(ctx, types.StringType, reorderedCQPParams)
	diags.Append(d...)
	if diags.HasError() {
		return CDNModel{}, false
	}
	// params is Required: a null/missing list from the API must become [].
	cqpParamsList, _ = NormalizeStringList(ctx, cqpParamsList)
	cqpObj, d := types.ObjectValueFrom(ctx, cacheQueryParamsAttrTypes, CDNCacheQueryParamsModel{
		Mode:   types.StringValue(cacheQueryParams.Mode),
		Params: cqpParamsList,
	})
	diags.Append(d...)
	if diags.HasError() {
		return CDNModel{}, false
	}
	state.CacheQueryParams = cqpObj

	ch := reorderByPlanOrder(refClientHeaders, clientHeaders, strKey)
	state.ClientHeaders, _ = types.ListValueFrom(ctx, types.StringType, ch)
	state.ClientHeaders, _ = NormalizeStringList(ctx, state.ClientHeaders)

	if clientIPHeader == nil {
		state.ClientIPHeader = types.StringNull()
	} else {
		state.ClientIPHeader = types.StringValue(*clientIPHeader)
	}

	uh := reorderByPlanOrder(refUpstreamHeaders, upstreamHeaders, strKey)
	state.UpstreamHeaders, _ = types.ListValueFrom(ctx, types.StringType, uh)
	state.UpstreamHeaders, _ = NormalizeStringList(ctx, state.UpstreamHeaders)

	state.HTTP2 = types.BoolValue(http2)

	ceModels := reorderByPlanOrder(refCacheErrors, cacheErrorEntriesToModels(cacheErrors), ceKey)
	state.CacheErrors = cacheErrorModelsToList(ctx, ceModels, diags)
	if diags.HasError() {
		return CDNModel{}, false
	}

	state.ContentCompression = types.ObjectNull(contentCompressionAttrTypes)
	if manageCompression {
		state.ContentCompression = contentCompressionFromAPI(ctx, contentCompression, diags)
		if diags.HasError() {
			return CDNModel{}, false
		}
	}

	state.AccessFilter = types.ObjectNull(accessFilterAttrTypes)
	if manageFilter {
		refFilter := accessFilterObjectToModel(ctx, ref.AccessFilter, diags)
		if diags.HasError() {
			return CDNModel{}, false
		}
		filterModel, d := accessFilterFromAPI(ctx, accessFilter, refFilter)
		diags.Append(d...)
		state.AccessFilter = accessFilterModelToObject(ctx, filterModel, diags)
		if diags.HasError() {
			return CDNModel{}, false
		}
	}

	state.WebP = types.Int64Value(webp)

	tlsV := reorderByPlanOrder(refTLSVersions, tlsVersions, strKey)
	state.TLSVersions, _ = types.ListValueFrom(ctx, types.StringType, tlsV)
	state.TLSVersions, _ = NormalizeStringList(ctx, state.TLSVersions)

	if ref.DefaultHost.IsUnknown() || ref.DefaultHost.IsNull() {
		state.DefaultHost = types.StringValue(defaultHost)
	} else {
		state.DefaultHost = ref.DefaultHost
	}

	return state, true
}

// cdnCacheErrorEntry represents the API structure for a CDN cache error entry.
type cdnCacheErrorEntry struct {
	Code    int64 `json:"code"`
	Timeout int64 `json:"timeout"`
}

var cacheErrorAttrTypes = map[string]attr.Type{
	"code":    types.Int64Type,
	"timeout": types.Int64Type,
}

var cacheQueryParamsAttrTypes = map[string]attr.Type{
	"mode":   types.StringType,
	"params": types.ListType{ElemType: types.StringType},
}

var cacheQueryParamNameRE = regexp.MustCompile(`^(?:[a-zA-Z0-9]|%[a-fA-F0-9]{2}|[-_.~])+$`)

// apiCacheQueryParams is the wire format for cache_query_params_set/get.
type apiCacheQueryParams struct {
	Mode   string   `json:"mode"`
	Params []string `json:"params"`
}

// updateCacheErrors calls the specified API method if the cache errors configuration has changed.
func (r *CDNResource) updateCacheErrors(ctx context.Context, apiPath, method string, plan, state types.List, diags *diag.Diagnostics) error {
	var planEntries, stateEntries []CDNCacheErrorEntryModel

	d := plan.ElementsAs(ctx, &planEntries, false)
	diags.Append(d...)
	if diags.HasError() {
		return fmt.Errorf("failed to parse plan %s", method)
	}

	if !IsNullOrUnknown(state) {
		d = state.ElementsAs(ctx, &stateEntries, false)
		diags.Append(d...)
		if diags.HasError() {
			return fmt.Errorf("failed to parse state %s", method)
		}
	}

	if cacheErrorEntriesEqual(planEntries, stateEntries) {
		return nil
	}

	params := make([]map[string]interface{}, len(planEntries))
	for i, e := range planEntries {
		params[i] = map[string]interface{}{
			"code":    e.Code.ValueInt64(),
			"timeout": e.Timeout.ValueInt64(),
		}
	}

	if _, err := r.client.MakeRequest(ctx, apiPath, method, params); err != nil {
		diags.AddError(fmt.Sprintf("Failed to update %s", method), err.Error())
		return err
	}

	return nil
}

// cacheErrorEntriesEqual compares two slices of CDNCacheErrorEntryModel for equality.
func cacheErrorEntriesEqual(a, b []CDNCacheErrorEntryModel) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Code.ValueInt64() != b[i].Code.ValueInt64() {
			return false
		}
		if a[i].Timeout.ValueInt64() != b[i].Timeout.ValueInt64() {
			return false
		}
	}
	return true
}

// cacheErrorEntriesToModels converts API cache error entries to model structs.
func cacheErrorEntriesToModels(entries []cdnCacheErrorEntry) []CDNCacheErrorEntryModel {
	models := make([]CDNCacheErrorEntryModel, len(entries))
	for i, e := range entries {
		models[i] = CDNCacheErrorEntryModel{
			Code:    types.Int64Value(e.Code),
			Timeout: types.Int64Value(e.Timeout),
		}
	}
	return models
}

// cacheErrorModelsToList converts model structs to a Terraform List value.
func cacheErrorModelsToList(ctx context.Context, models []CDNCacheErrorEntryModel, diags *diag.Diagnostics) types.List {
	elems := make([]attr.Value, len(models))
	for i, m := range models {
		obj, d := types.ObjectValueFrom(ctx, cacheErrorAttrTypes, m)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: cacheErrorAttrTypes})
		}
		elems[i] = obj
	}
	list, d := types.ListValue(types.ObjectType{AttrTypes: cacheErrorAttrTypes}, elems)
	diags.Append(d...)
	return list
}

// parseCacheControl converts the API response for cache_control_get into a
// normalised string for the Terraform state: "cdn", "origin", or a numeric
// string like "21600". The API may return a JSON string or a JSON number.
func parseCacheControl(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil // "cdn" or "origin"
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return strconv.FormatInt(n, 10), nil
	}
	return "", fmt.Errorf("unexpected cache_control value: %s", string(raw))
}

// cacheControlToAPI converts the Terraform string value back to the type
// expected by cache_control_set: "cdn"/"origin" as string, numeric as int.
func cacheControlToAPI(v string) interface{} {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n
	}
	return v
}
