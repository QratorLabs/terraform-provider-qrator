package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// CDNModel defines the model for a CDN configuration.
type CDNModel struct {
	DomainID types.Int64 `tfsdk:"domain_id"`

	AccessControlAllowOrigin types.List  `tfsdk:"access_control_allow_origin"`
	CacheControl             types.Bool  `tfsdk:"cache_control"`
	RedirectCode             types.Int64 `tfsdk:"redirect_code"`

	CacheIgnoreParams types.Bool   `tfsdk:"cache_ignore_params"`
	ClientHeaders     types.List   `tfsdk:"client_headers"`
	ClientIPHeader    types.String `tfsdk:"client_ip_header"`

	UpstreamHeaders types.List `tfsdk:"upstream_headers"`

	ClientNoCache types.Bool `tfsdk:"client_no_cache"`
	HTTP2         types.Bool `tfsdk:"http2"`

	CacheErrors          types.List `tfsdk:"cache_errors"`
	CacheErrorsPermanent types.List `tfsdk:"cache_errors_permanent"`
	CompressDisabled     types.List `tfsdk:"compress_disabled"`

	SNI        types.List `tfsdk:"sni"`
	BlockedURI types.List `tfsdk:"blocked_uri"`
	WhiteURI   types.List `tfsdk:"white_uri"`
}

// CDNSNIEntryModel defines the model for a CDN SNI entry.
type CDNSNIEntryModel struct {
	Host        types.String `tfsdk:"host"`
	Certificate types.Int64  `tfsdk:"certificate"`
}

// CDNBlockedURIEntryModel defines the model for a CDN blocked URI entry.
type CDNBlockedURIEntryModel struct {
	URI  types.String `tfsdk:"uri"`
	Code types.Int64  `tfsdk:"code"`
}

// CDNCacheErrorEntryModel defines the model for a CDN cache error entry.
type CDNCacheErrorEntryModel struct {
	Code    types.Int64 `tfsdk:"code"`
	Timeout types.Int64 `tfsdk:"timeout"`
}
