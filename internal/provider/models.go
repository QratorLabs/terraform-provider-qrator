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

// DomainModel defines the model for a domain resource.
type DomainModel struct {
	ID       types.Int64          `tfsdk:"id"`
	Name     types.String         `tfsdk:"name"`
	Services *DomainServicesModel `tfsdk:"services"`
	SNI      types.List           `tfsdk:"sni"`
}

// DomainSNIEntryModel defines the model for a domain SNI entry.
type DomainSNIEntryModel struct {
	Host        types.String `tfsdk:"host"`
	Certificate types.Int64  `tfsdk:"certificate"`
}

// DomainServicesModel groups all service type lists.
type DomainServicesModel struct {
	HTTP      []DomainServiceHTTPModel     `tfsdk:"http"`
	NAT       []DomainServiceNATModel      `tfsdk:"nat"`
	NATAll    []DomainServiceNATAllModel   `tfsdk:"nat_all"`
	TCPProxy  []DomainServiceTCPProxyModel `tfsdk:"tcpproxy"`
	WebSocket []DomainServiceWSModel       `tfsdk:"websocket"`
}

// DomainServiceHTTPModel represents an HTTP service entry.
type DomainServiceHTTPModel struct {
	ID                  types.Int64                 `tfsdk:"id"`
	Port                types.Int64                 `tfsdk:"port"`
	SSL                 types.Bool                  `tfsdk:"ssl"`
	HTTP2               types.Bool                  `tfsdk:"http2"`
	DefaultDrop         types.Bool                  `tfsdk:"default_drop"`
	UpstreamBalancer    types.String                `tfsdk:"upstream_balancer"`
	UpstreamWeights     types.Bool                  `tfsdk:"upstream_weights"`
	UpstreamBackups     types.Bool                  `tfsdk:"upstream_backups"`
	UpstreamSSL         types.Bool                  `tfsdk:"upstream_ssl"`
	UpstreamSNIName     types.String                `tfsdk:"upstream_sni_name"`
	UpstreamSNIOverride types.Bool                  `tfsdk:"upstream_sni_override"`
	Upstreams           []DomainUpstreamServerModel `tfsdk:"upstreams"`
}

// DomainServiceNATModel represents a NAT (tcp/udp) service entry.
type DomainServiceNATModel struct {
	ID           types.Int64  `tfsdk:"id"`
	Port         types.Int64  `tfsdk:"port"`
	Proto        types.String `tfsdk:"proto"`
	DefaultDrop  types.Bool   `tfsdk:"default_drop"`
	DropAmp      types.Bool   `tfsdk:"drop_amp"`
	RateLimit    types.Int64  `tfsdk:"rate_limit"`
	UpstreamIP   types.String `tfsdk:"upstream_ip"`
	UpstreamPort types.Int64  `tfsdk:"upstream_port"`
}

// DomainServiceNATAllModel represents a nat-all (tcp/udp) service entry.
type DomainServiceNATAllModel struct {
	ID          types.Int64  `tfsdk:"id"`
	Proto       types.String `tfsdk:"proto"`
	DefaultDrop types.Bool   `tfsdk:"default_drop"`
	DropAmp     types.Bool   `tfsdk:"drop_amp"`
	RateLimit   types.Int64  `tfsdk:"rate_limit"`
	UpstreamIP  types.String `tfsdk:"upstream_ip"`
}

// DomainServiceTCPProxyModel represents a tcpproxy service entry.
type DomainServiceTCPProxyModel struct {
	ID            types.Int64                 `tfsdk:"id"`
	Port          types.Int64                 `tfsdk:"port"`
	DefaultDrop   types.Bool                  `tfsdk:"default_drop"`
	ProxyProtocol types.Int64                 `tfsdk:"proxy_protocol"`
	Upstreams     []DomainUpstreamServerModel `tfsdk:"upstreams"`
}

// DomainServiceWSModel represents a websocket service entry.
type DomainServiceWSModel struct {
	ID          types.Int64                 `tfsdk:"id"`
	Port        types.Int64                 `tfsdk:"port"`
	SSL         types.Bool                  `tfsdk:"ssl"`
	DefaultDrop types.Bool                  `tfsdk:"default_drop"`
	UpstreamSSL types.Bool                  `tfsdk:"upstream_ssl"`
	Upstreams   []DomainUpstreamServerModel `tfsdk:"upstreams"`
}

// DomainUpstreamServerModel represents a single upstream server.
type DomainUpstreamServerModel struct {
	IP        types.String `tfsdk:"ip"`
	DNSRecord types.String `tfsdk:"dns_record"`
	Port      types.Int64  `tfsdk:"port"`
	Weight    types.Int64  `tfsdk:"weight"`
	Type      types.String `tfsdk:"type"`
	Name      types.String `tfsdk:"name"`
}
