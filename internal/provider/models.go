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

	SNI types.List `tfsdk:"sni"`
}

// CDNSNIEntryModel defines the model for a CDN SNI entry.
type CDNSNIEntryModel struct {
	Host        types.String `tfsdk:"host"`
	Certificate types.Int64  `tfsdk:"certificate"`
}
