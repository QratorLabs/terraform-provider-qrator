package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Schema history of qrator_cdn:
//
//	v0 → v1: cache_ignore_params (bool) replaced by cache_query_params,
//	         cache_errors_permanent removed.
//	v1 → v2: blocked_uri and white_uri replaced by access_filter
//	         (Qrator API v1.5.21 access filter), client_no_cache removed
//	         (no longer supported by the API), compress_disabled replaced by
//	         content_compression.
//
// The framework does not chain upgraders, so every upgrader produces the
// current (v2) state.

// cdnModelV1 is the state model of schema v1.
type cdnModelV1 struct {
	DomainID                 types.Int64  `tfsdk:"domain_id"`
	AccessControlAllowOrigin types.List   `tfsdk:"access_control_allow_origin"`
	CacheControl             types.String `tfsdk:"cache_control"`
	ClientNoCache            types.Bool   `tfsdk:"client_no_cache"`
	RedirectCode             types.Int64  `tfsdk:"redirect_code"`
	CacheQueryParams         types.Object `tfsdk:"cache_query_params"`
	ClientHeaders            types.List   `tfsdk:"client_headers"`
	ClientIPHeader           types.String `tfsdk:"client_ip_header"`
	UpstreamHeaders          types.List   `tfsdk:"upstream_headers"`
	HTTP2                    types.Bool   `tfsdk:"http2"`
	CacheErrors              types.List   `tfsdk:"cache_errors"`
	CompressDisabled         types.List   `tfsdk:"compress_disabled"`
	BlockedURI               types.List   `tfsdk:"blocked_uri"`
	WhiteURI                 types.List   `tfsdk:"white_uri"`
	WebP                     types.Int64  `tfsdk:"webp"`
	TLSVersions              types.List   `tfsdk:"tls_versions"`
	DefaultHost              types.String `tfsdk:"default_host"`
}

// cdnModelV0 is the state model of schema v0.
type cdnModelV0 struct {
	DomainID                 types.Int64  `tfsdk:"domain_id"`
	AccessControlAllowOrigin types.List   `tfsdk:"access_control_allow_origin"`
	CacheControl             types.String `tfsdk:"cache_control"`
	ClientNoCache            types.Bool   `tfsdk:"client_no_cache"`
	RedirectCode             types.Int64  `tfsdk:"redirect_code"`
	CacheIgnoreParams        types.Bool   `tfsdk:"cache_ignore_params"`
	ClientHeaders            types.List   `tfsdk:"client_headers"`
	ClientIPHeader           types.String `tfsdk:"client_ip_header"`
	UpstreamHeaders          types.List   `tfsdk:"upstream_headers"`
	HTTP2                    types.Bool   `tfsdk:"http2"`
	CacheErrors              types.List   `tfsdk:"cache_errors"`
	CacheErrorsPermanent     types.List   `tfsdk:"cache_errors_permanent"`
	CompressDisabled         types.List   `tfsdk:"compress_disabled"`
	BlockedURI               types.List   `tfsdk:"blocked_uri"`
	WhiteURI                 types.List   `tfsdk:"white_uri"`
	WebP                     types.Int64  `tfsdk:"webp"`
	TLSVersions              types.List   `tfsdk:"tls_versions"`
	DefaultHost              types.String `tfsdk:"default_host"`
}

// cdnPriorSchemaAttributes returns the attributes shared by schemas v0 and v1.
func cdnPriorSchemaAttributes() map[string]schema.Attribute {
	codeTimeout := schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"code":    schema.Int64Attribute{Required: true},
			"timeout": schema.Int64Attribute{Required: true},
		},
	}
	return map[string]schema.Attribute{
		"domain_id":                   schema.Int64Attribute{Required: true},
		"access_control_allow_origin": schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType},
		"cache_control":               schema.StringAttribute{Optional: true, Computed: true},
		"client_no_cache":             schema.BoolAttribute{Optional: true, Computed: true},
		"redirect_code":               schema.Int64Attribute{Optional: true},
		"client_headers":              schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType},
		"client_ip_header":            schema.StringAttribute{Optional: true, Computed: true},
		"upstream_headers":            schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType},
		"http2":                       schema.BoolAttribute{Optional: true, Computed: true},
		"cache_errors":                schema.ListNestedAttribute{Optional: true, Computed: true, NestedObject: codeTimeout},
		"compress_disabled":           schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType},
		"blocked_uri": schema.ListNestedAttribute{
			Optional: true, Computed: true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"uri":  schema.StringAttribute{Required: true},
					"code": schema.Int64Attribute{Required: true},
				},
			},
		},
		"white_uri":    schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType},
		"webp":         schema.Int64Attribute{Optional: true, Computed: true},
		"tls_versions": schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType},
		"default_host": schema.StringAttribute{Computed: true},
	}
}

func cdnPriorSchemaV0() *schema.Schema {
	attrs := cdnPriorSchemaAttributes()
	attrs["cache_ignore_params"] = schema.BoolAttribute{Optional: true, Computed: true}
	attrs["cache_errors_permanent"] = schema.ListNestedAttribute{
		Optional: true, Computed: true,
		NestedObject: schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"code":    schema.Int64Attribute{Required: true},
				"timeout": schema.Int64Attribute{Required: true},
			},
		},
	}
	return &schema.Schema{Attributes: attrs}
}

func cdnPriorSchemaV1() *schema.Schema {
	attrs := cdnPriorSchemaAttributes()
	attrs["cache_query_params"] = schema.SingleNestedAttribute{
		Optional: true, Computed: true,
		Attributes: map[string]schema.Attribute{
			"mode":   schema.StringAttribute{Required: true},
			"params": schema.ListAttribute{Required: true, ElementType: types.StringType},
		},
	}
	return &schema.Schema{Attributes: attrs}
}

func (r *CDNResource) UpgradeState(ctx context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{
		0: {
			PriorSchema: cdnPriorSchemaV0(),
			StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
				var v0 cdnModelV0
				resp.Diagnostics.Append(req.State.Get(ctx, &v0)...)
				if resp.Diagnostics.HasError() {
					return
				}
				v1 := upgradeCDNStateV0ToV1(ctx, v0, &resp.Diagnostics)
				if resp.Diagnostics.HasError() {
					return
				}
				v2 := upgradeCDNStateV1ToV2(ctx, v1, &resp.Diagnostics)
				if resp.Diagnostics.HasError() {
					return
				}
				resp.Diagnostics.Append(resp.State.Set(ctx, &v2)...)
			},
		},
		1: {
			PriorSchema: cdnPriorSchemaV1(),
			StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
				var v1 cdnModelV1
				resp.Diagnostics.Append(req.State.Get(ctx, &v1)...)
				if resp.Diagnostics.HasError() {
					return
				}
				v2 := upgradeCDNStateV1ToV2(ctx, v1, &resp.Diagnostics)
				if resp.Diagnostics.HasError() {
					return
				}
				resp.Diagnostics.Append(resp.State.Set(ctx, &v2)...)
			},
		},
	}
}

// upgradeCDNStateV0ToV1 converts cache_ignore_params to cache_query_params:
//
//	cache_ignore_params = true  → mode "use",    params [] (ignore all: whitelist of nothing)
//	cache_ignore_params = false → mode "ignore", params [] (use all: blacklist of nothing)
//
// cache_errors_permanent is dropped.
func upgradeCDNStateV0ToV1(ctx context.Context, v0 cdnModelV0, diags *diag.Diagnostics) cdnModelV1 {
	mode := "ignore"
	if !v0.CacheIgnoreParams.IsNull() && v0.CacheIgnoreParams.ValueBool() {
		mode = "use"
	}
	cqpObj, d := types.ObjectValueFrom(ctx, cacheQueryParamsAttrTypes, CDNCacheQueryParamsModel{
		Mode:   types.StringValue(mode),
		Params: types.ListValueMust(types.StringType, []attr.Value{}),
	})
	diags.Append(d...)

	return cdnModelV1{
		DomainID:                 v0.DomainID,
		AccessControlAllowOrigin: v0.AccessControlAllowOrigin,
		CacheControl:             v0.CacheControl,
		ClientNoCache:            v0.ClientNoCache,
		RedirectCode:             v0.RedirectCode,
		CacheQueryParams:         cqpObj,
		ClientHeaders:            v0.ClientHeaders,
		ClientIPHeader:           v0.ClientIPHeader,
		UpstreamHeaders:          v0.UpstreamHeaders,
		HTTP2:                    v0.HTTP2,
		CacheErrors:              v0.CacheErrors,
		CompressDisabled:         v0.CompressDisabled,
		BlockedURI:               v0.BlockedURI,
		WhiteURI:                 v0.WhiteURI,
		WebP:                     v0.WebP,
		TLSVersions:              v0.TLSVersions,
		DefaultHost:              v0.DefaultHost,
	}
}

// whiteURIMigratedStatusCode is the code the API assigns to white_uri rules
// migrated to the uri allow list (the CDN used to answer 404 for them).
const whiteURIMigratedStatusCode = 404

// upgradeCDNStateV1ToV2 drops client_no_cache, converts compress_disabled to
// content_compression and moves blocked_uri and white_uri into access_filter.uri,
// mirroring the server-side migration of API v1.5.21:
//
//	blocked_uri[{uri, code}] → access_filter.uri.deny[{regex, status_code}]
//	white_uri[...]           → access_filter.uri.allow, allow_status_code = 404
//
// When neither had entries, access_filter is left null and is filled in by the
// next refresh.
func upgradeCDNStateV1ToV2(ctx context.Context, v1 cdnModelV1, diags *diag.Diagnostics) CDNModel {
	v2 := CDNModel{
		DomainID:                 v1.DomainID,
		AccessControlAllowOrigin: v1.AccessControlAllowOrigin,
		CacheControl:             v1.CacheControl,
		RedirectCode:             v1.RedirectCode,
		CacheQueryParams:         v1.CacheQueryParams,
		ClientHeaders:            v1.ClientHeaders,
		ClientIPHeader:           v1.ClientIPHeader,
		UpstreamHeaders:          v1.UpstreamHeaders,
		HTTP2:                    v1.HTTP2,
		CacheErrors:              v1.CacheErrors,
		ContentCompression:       upgradeCompressDisabled(ctx, v1.CompressDisabled, diags),
		AccessFilter:             types.ObjectNull(accessFilterAttrTypes),
		WebP:                     v1.WebP,
		TLSVersions:              v1.TLSVersions,
		DefaultHost:              v1.DefaultHost,
	}

	var blocked []CDNBlockedURIEntryModel
	if !IsNullOrUnknown(v1.BlockedURI) {
		diags.Append(v1.BlockedURI.ElementsAs(ctx, &blocked, false)...)
	}
	var white []string
	if !IsNullOrUnknown(v1.WhiteURI) {
		diags.Append(v1.WhiteURI.ElementsAs(ctx, &white, false)...)
	}
	if diags.HasError() || (len(blocked) == 0 && len(white) == 0) {
		return v2
	}

	uri := &CDNFilterURIRulesModel{
		Allow:           types.ListNull(types.StringType),
		AllowStatusCode: types.Int64Null(),
		Deny:            types.ListNull(types.ObjectType{AttrTypes: filterDenyRegexAttrTypes}),
	}
	if len(white) > 0 {
		l, d := types.ListValueFrom(ctx, types.StringType, white)
		diags.Append(d...)
		uri.Allow = l
		uri.AllowStatusCode = types.Int64Value(whiteURIMigratedStatusCode)
	}
	if len(blocked) > 0 {
		deny := make([]CDNFilterDenyRegexModel, len(blocked))
		for i, b := range blocked {
			deny[i] = CDNFilterDenyRegexModel{Regex: b.URI, StatusCode: b.Code}
		}
		l, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: filterDenyRegexAttrTypes}, deny)
		diags.Append(d...)
		uri.Deny = l
	}

	v2.AccessFilter = accessFilterModelToObject(ctx, CDNAccessFilterModel{
		SkipIPs: types.SetNull(types.StringType),
		URI:     uri,
	}, diags)
	return v2
}

// compressionAlgorithms lists the keys of CdnContentCompression.
var compressionAlgorithms = []string{"gzip", "br", "deflate", "zstd"}

// upgradeCompressDisabled converts compress_disabled to content_compression:
// a disabled algorithm gets an empty list, the others keep the API default
// ["*"] (compress_disabled had no way to restrict MIME types). An empty
// compress_disabled leaves content_compression unmanaged (null).
func upgradeCompressDisabled(ctx context.Context, compressDisabled types.List, diags *diag.Diagnostics) types.Object {
	var disabled []string
	if !IsNullOrUnknown(compressDisabled) {
		diags.Append(compressDisabled.ElementsAs(ctx, &disabled, false)...)
	}
	if len(disabled) == 0 {
		return types.ObjectNull(contentCompressionAttrTypes)
	}
	off := make(map[string]bool, len(disabled))
	for _, a := range disabled {
		off[a] = true
	}
	lists := make(map[string][]string, len(compressionAlgorithms))
	for _, a := range compressionAlgorithms {
		if off[a] {
			lists[a] = []string{}
		} else {
			lists[a] = []string{"*"}
		}
	}
	return contentCompressionFromAPI(ctx, apiContentCompression{
		Gzip: lists["gzip"], Br: lists["br"], Deflate: lists["deflate"], Zstd: lists["zstd"],
	}, diags)
}
