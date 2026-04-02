package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
	"golang.org/x/sync/errgroup"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type CDNResource struct {
	client *client.QratorClient
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
			},
			"cache_control": schema.StringAttribute{
				Description: `Controls cache TTL. "cdn" — CDN controls with default 6h; a number (7200–604800) — CDN controls with custom timeout in seconds; "origin" — origin Cache-Control/Expires headers are used.`,
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("cdn"),
			},
			"client_no_cache": schema.BoolAttribute{
				Description: "If enabled, no cache headers beside cache-control: no-cache are sent to client.",
				Optional:    true,
				Computed:    true,
			},
			"redirect_code": schema.Int64Attribute{
				Description: "HTTP-to-HTTPS redirect status code returned by CDN edge nodes. Must be 301, 302, 307, or 308. Leave unset to disable.",
				Optional:    true,
				Validators: []validator.Int64{
					int64validator.OneOf(301, 302, 307, 308),
				},
			},
			"cache_ignore_params": schema.BoolAttribute{
				Description: "Whether to ignore query parameters when caching.",
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				Computed:    true,
			},
			"client_headers": schema.ListAttribute{
				Description: "Headers that will be added to every response sent by CDN to client. Format: header:value.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
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
			},
			"blocked_uri": schema.ListNestedAttribute{
				Description: "List of URI patterns to block. Each entry specifies a regex pattern and an HTTP response code.",
				Optional:    true,
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"uri": schema.StringAttribute{
							Description: "URI regex pattern to block.",
							Required:    true,
						},
						"code": schema.Int64Attribute{
							Description: "HTTP response code to return for blocked URIs (e.g. 403, 404).",
							Required:    true,
						},
					},
				},
			},
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
							Description: "Timeout in milliseconds before the next request is allowed (60000–300000).",
							Required:    true,
							Validators: []validator.Int64{
								int64validator.Between(60000, 300000),
							},
						},
					},
				},
			},
			"cache_errors_permanent": schema.ListNestedAttribute{
				Description: "Permanently cache error responses per client IP. If upstream returns a matching status code, the response is cached for the client IP for the specified timeout (ms).",
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
							Description: "Timeout in milliseconds before the next request from the same client IP is allowed (60000–300000).",
							Required:    true,
							Validators: []validator.Int64{
								int64validator.Between(60000, 300000),
							},
						},
					},
				},
			},
			"compress_disabled": schema.ListAttribute{
				Description: "List of compression algorithms to disable. Allowed values: gzip, deflate, br.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"white_uri": schema.ListAttribute{
				Description: "List of allowed URI regex patterns. If set, requests not matching any pattern get a 404 response. Leave empty to disable.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"webp": schema.Int64Attribute{
				Description: "WebP image compression quality (0-100). When set, enables on-the-fly conversion of images to WebP format. Omit or set to null to disable.",
				Optional:    true,
				Computed:    true,
				Validators:  []validator.Int64{int64validator.Between(0, 100)},
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
	result, ok := r.readCDNModel(ctx, domainID, plan.DefaultHost, &resp.Diagnostics)
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
	result, ok := r.readCDNModel(ctx, domainID, plan.DefaultHost, &resp.Diagnostics)
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

	result, ok := r.readCDNModel(ctx, state.DomainID.ValueInt64(), state.DefaultHost, &resp.Diagnostics)
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

	// client_no_cache
	if !IsNullOrUnknown(plan.ClientNoCache) &&
		(state.ClientNoCache.IsNull() || plan.ClientNoCache.ValueBool() != state.ClientNoCache.ValueBool()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "client_no_cache_set", plan.ClientNoCache.ValueBool()); err != nil {
			diags.AddError("Failed to update client_no_cache", err.Error())
			return false
		}
	}

	// cache_ignore_params
	if !IsNullOrUnknown(plan.CacheIgnoreParams) &&
		(state.CacheIgnoreParams.IsNull() || plan.CacheIgnoreParams.ValueBool() != state.CacheIgnoreParams.ValueBool()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "cache_ignore_params_set", plan.CacheIgnoreParams.ValueBool()); err != nil {
			diags.AddError("Failed to update cache_ignore_params", err.Error())
			return false
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

	// cache_errors_permanent
	if !IsNullOrUnknown(plan.CacheErrorsPermanent) {
		if err := r.updateCacheErrors(ctx, apiPath, "cache_errors_permanent_set", plan.CacheErrorsPermanent, state.CacheErrorsPermanent, diags); err != nil {
			return false
		}
	}

	// compress_disabled
	if !IsNullOrUnknown(plan.CompressDisabled) &&
		ShouldUpdateList(plan.CompressDisabled, state.CompressDisabled, true) {
		var values []string
		plan.CompressDisabled.ElementsAs(ctx, &values, false)
		if _, err := r.client.MakeRequest(ctx, apiPath, "compress_disabled_set", values); err != nil {
			diags.AddError("Failed to update compress_disabled", err.Error())
			return false
		}
	}

	// blocked_uri
	if !IsNullOrUnknown(plan.BlockedURI) {
		if err := r.updateBlockedURI(ctx, apiPath, plan.BlockedURI, state.BlockedURI, diags); err != nil {
			return false
		}
	}

	// white_uri
	if !IsNullOrUnknown(plan.WhiteURI) &&
		ShouldUpdateList(plan.WhiteURI, state.WhiteURI, true) {
		var values []string
		plan.WhiteURI.ElementsAs(ctx, &values, false)
		if _, err := r.client.MakeRequest(ctx, apiPath, "white_uri_set", values); err != nil {
			diags.AddError("Failed to update white_uri", err.Error())
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

	return true
}

// readCDNModel fetches all CDN settings from the API and returns a populated CDNModel.
// prevDefaultHost is the already-known default_host value; if known, the API call is skipped.
func (r *CDNResource) readCDNModel(ctx context.Context, domainID int64, prevDefaultHost types.String, diags *diag.Diagnostics) (CDNModel, bool) {
	apiPath := fmt.Sprintf("/request/cdn/%d", domainID)

	var (
		accessControlAllowOrigin []string
		cacheControlRaw          json.RawMessage
		redirectCode             *int64
		clientNoCache            bool
		cacheIgnoreParams        bool
		clientHeaders            []string
		clientIPHeader           *string
		webp                     int64
		upstreamHeaders          []string
		http2                    bool
		cacheErrors              []cdnCacheErrorEntry
		cacheErrorsPermanent     []cdnCacheErrorEntry
		compressDisabled         []string
		blockedURIEntries        []cdnBlockedURIEntry
		whiteURI                 []string
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
		v, err := r.client.MakeRequest(gctx, apiPath, "client_no_cache_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &clientNoCache)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "cache_ignore_params_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &cacheIgnoreParams)
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

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "cache_errors_permanent_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &cacheErrorsPermanent)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "compress_disabled_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &compressDisabled)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "blocked_uri_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &blockedURIEntries)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "white_uri_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &whiteURI)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "webp_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &webp)
	})

	if prevDefaultHost.IsUnknown() || prevDefaultHost.IsNull() {
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

	var state CDNModel
	state.DomainID = types.Int64Value(domainID)
	state.AccessControlAllowOrigin, _ = types.ListValueFrom(ctx, types.StringType, accessControlAllowOrigin)
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
	state.ClientNoCache = types.BoolValue(clientNoCache)
	state.CacheIgnoreParams = types.BoolValue(cacheIgnoreParams)
	state.ClientHeaders, _ = types.ListValueFrom(ctx, types.StringType, clientHeaders)
	if clientIPHeader == nil {
		state.ClientIPHeader = types.StringNull()
	} else {
		state.ClientIPHeader = types.StringValue(*clientIPHeader)
	}
	state.UpstreamHeaders, _ = types.ListValueFrom(ctx, types.StringType, upstreamHeaders)

	state.AccessControlAllowOrigin, _ = NormalizeStringList(ctx, state.AccessControlAllowOrigin)
	state.ClientHeaders, _ = NormalizeStringList(ctx, state.ClientHeaders)
	state.UpstreamHeaders, _ = NormalizeStringList(ctx, state.UpstreamHeaders)

	state.HTTP2 = types.BoolValue(http2)

	state.CacheErrors = cacheErrorEntriesToList(ctx, cacheErrors, diags)
	if diags.HasError() {
		return CDNModel{}, false
	}

	state.CacheErrorsPermanent = cacheErrorEntriesToList(ctx, cacheErrorsPermanent, diags)
	if diags.HasError() {
		return CDNModel{}, false
	}

	state.CompressDisabled, _ = types.ListValueFrom(ctx, types.StringType, compressDisabled)
	state.CompressDisabled, _ = NormalizeStringList(ctx, state.CompressDisabled)

	state.BlockedURI = blockedURIEntriesToList(ctx, blockedURIEntries, diags)
	if diags.HasError() {
		return CDNModel{}, false
	}

	state.WhiteURI, _ = types.ListValueFrom(ctx, types.StringType, whiteURI)
	state.WhiteURI, _ = NormalizeStringList(ctx, state.WhiteURI)

	state.WebP = types.Int64Value(webp)
	if prevDefaultHost.IsUnknown() || prevDefaultHost.IsNull() {
		state.DefaultHost = types.StringValue(defaultHost)
	} else {
		state.DefaultHost = prevDefaultHost
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

var blockedURIAttrTypes = map[string]attr.Type{
	"uri":  types.StringType,
	"code": types.Int64Type,
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

// cacheErrorEntriesToList converts API cache error entries to a Terraform List value.
func cacheErrorEntriesToList(ctx context.Context, entries []cdnCacheErrorEntry, diags *diag.Diagnostics) types.List {
	models := make([]CDNCacheErrorEntryModel, len(entries))
	for i, e := range entries {
		models[i] = CDNCacheErrorEntryModel{
			Code:    types.Int64Value(e.Code),
			Timeout: types.Int64Value(e.Timeout),
		}
	}

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

// cdnBlockedURIEntry represents the API structure for a CDN blocked URI entry.
type cdnBlockedURIEntry struct {
	URI  string `json:"uri"`
	Code int64  `json:"code"`
}

// updateBlockedURI calls blocked_uri_set if the blocked URI configuration has changed.
func (r *CDNResource) updateBlockedURI(ctx context.Context, apiPath string, plan, state types.List, diags *diag.Diagnostics) error {
	var planEntries, stateEntries []CDNBlockedURIEntryModel

	d := plan.ElementsAs(ctx, &planEntries, false)
	diags.Append(d...)
	if diags.HasError() {
		return fmt.Errorf("failed to parse plan blocked_uri")
	}

	if !IsNullOrUnknown(state) {
		d = state.ElementsAs(ctx, &stateEntries, false)
		diags.Append(d...)
		if diags.HasError() {
			return fmt.Errorf("failed to parse state blocked_uri")
		}
	}

	if blockedURIEntriesEqual(planEntries, stateEntries) {
		return nil
	}

	params := make([]map[string]interface{}, len(planEntries))
	for i, e := range planEntries {
		params[i] = map[string]interface{}{
			"uri":  e.URI.ValueString(),
			"code": e.Code.ValueInt64(),
		}
	}

	if _, err := r.client.MakeRequest(ctx, apiPath, "blocked_uri_set", params); err != nil {
		diags.AddError("Failed to update blocked_uri", err.Error())
		return err
	}

	return nil
}

// blockedURIEntriesEqual compares two slices of CDNBlockedURIEntryModel for equality.
func blockedURIEntriesEqual(a, b []CDNBlockedURIEntryModel) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].URI.ValueString() != b[i].URI.ValueString() {
			return false
		}
		if a[i].Code.ValueInt64() != b[i].Code.ValueInt64() {
			return false
		}
	}
	return true
}

// blockedURIEntriesToList converts API blocked URI entries to a Terraform List value.
func blockedURIEntriesToList(ctx context.Context, entries []cdnBlockedURIEntry, diags *diag.Diagnostics) types.List {
	models := make([]CDNBlockedURIEntryModel, len(entries))
	for i, e := range entries {
		models[i] = CDNBlockedURIEntryModel{
			URI:  types.StringValue(e.URI),
			Code: types.Int64Value(e.Code),
		}
	}

	elems := make([]attr.Value, len(models))
	for i, m := range models {
		obj, d := types.ObjectValueFrom(ctx, blockedURIAttrTypes, m)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: blockedURIAttrTypes})
		}
		elems[i] = obj
	}

	list, d := types.ListValue(types.ObjectType{AttrTypes: blockedURIAttrTypes}, elems)
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
