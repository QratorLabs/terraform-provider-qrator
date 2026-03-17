package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// CDNModel defines the model for a CDN configuration.
type CDNModel struct {
	DomainID types.Int64 `tfsdk:"domain_id"`

	AccessControlAllowOrigin types.List  `tfsdk:"access_control_allow_origin"`
	CacheControl             types.String `tfsdk:"cache_control"`
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

	BlockedURI types.List `tfsdk:"blocked_uri"`
	WhiteURI   types.List `tfsdk:"white_uri"`

	WebP types.Int64 `tfsdk:"webp"`
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

// ---------------------------------------------------------------------------
// Domain services models
// ---------------------------------------------------------------------------

// DomainServicesResourceModel defines the model for the qrator_domain_services resource.
type DomainServicesResourceModel struct {
	DomainID  types.Int64                  `tfsdk:"domain_id"`
	HTTP      []DomainServiceHTTPModel     `tfsdk:"http"`
	NAT       []DomainServiceNATModel      `tfsdk:"nat"`
	NATAll    []DomainServiceNATAllModel   `tfsdk:"nat_all"`
	TCPProxy  []DomainServiceTCPProxyModel `tfsdk:"tcpproxy"`
	WebSocket []DomainServiceWSModel       `tfsdk:"websocket"`
}

// SNIEntryModel defines the model for a domain/service SNI entry.
type SNIEntryModel struct {
	LinkID      types.Int64  `tfsdk:"link_id"`
	Host        types.String `tfsdk:"host"`
	Certificate types.Int64  `tfsdk:"certificate"`
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

// IPListEntryModel defines a single IP entry (whitelist or blacklist).
type IPListEntryModel struct {
	IP      types.String `tfsdk:"ip"`
	TTL     types.Int64  `tfsdk:"ttl"`
	Comment types.String `tfsdk:"comment"`
}

// ---------------------------------------------------------------------------
// Service services models
// ---------------------------------------------------------------------------

// ServiceServicesResourceModel defines the model for the qrator_service_services resource.
type ServiceServicesResourceModel struct {
	ServiceID          types.Int64           `tfsdk:"service_id"`
	DNS                []ServiceDNSModel     `tfsdk:"dns"`
	HTTP               []ServiceHTTPModel    `tfsdk:"http"`
	ICMP               []ServiceICMPModel    `tfsdk:"icmp"`
	NAT                []ServiceNATModel     `tfsdk:"nat"`
	AnyIngressEgress   []ServiceAnyIEModel   `tfsdk:"any_ingress_egress"`
	ProtoIngressEgress []ServiceProtoIEModel `tfsdk:"proto_ingress_egress"`
	TCPIngressEgress   []ServiceTCPIEModel   `tfsdk:"tcp_ingress_egress"`
	TCPEgress          []ServiceTCPEModel    `tfsdk:"tcp_egress"`
	FragIngressEgress  []ServiceFragIEModel  `tfsdk:"frag_ingress_egress"`
}

// ServiceDNSModel represents a DNS service entry.
type ServiceDNSModel struct {
	ID          types.Int64 `tfsdk:"id"`
	Port        types.Int64 `tfsdk:"port"`
	DefaultDrop types.Bool  `tfsdk:"default_drop"`
}

// ServiceHTTPUpstreamModel represents upstream settings for an HTTP service entry.
type ServiceHTTPUpstreamModel struct {
	SSL         types.Bool   `tfsdk:"ssl"`
	SNIName     types.String `tfsdk:"sni_name"`
	SNIOverride types.Bool   `tfsdk:"sni_override"`
}

// ServiceHTTPModel represents an HTTP service entry (service entity).
type ServiceHTTPModel struct {
	ID          types.Int64               `tfsdk:"id"`
	Port        types.Int64               `tfsdk:"port"`
	SSL         types.Bool                `tfsdk:"ssl"`
	HTTP2       types.Bool                `tfsdk:"http2"`
	DefaultDrop types.Bool                `tfsdk:"default_drop"`
	Upstream    *ServiceHTTPUpstreamModel `tfsdk:"upstream"`
}

// ServiceICMPModel represents an ICMP service entry.
type ServiceICMPModel struct {
	ID          types.Int64 `tfsdk:"id"`
	DefaultDrop types.Bool  `tfsdk:"default_drop"`
	RateLimit   types.Int64 `tfsdk:"rate_limit"`
}

// ServiceNATModel represents a NAT (tcp/udp) service entry (service entity — no upstream).
type ServiceNATModel struct {
	ID          types.Int64  `tfsdk:"id"`
	Port        types.Int64  `tfsdk:"port"`
	Proto       types.String `tfsdk:"proto"`
	DefaultDrop types.Bool   `tfsdk:"default_drop"`
	DropAmp     types.Bool   `tfsdk:"drop_amp"`
	RateLimit   types.Int64  `tfsdk:"rate_limit"`
}

// ServiceAnyIEModel represents an any-ingress-egress service entry.
type ServiceAnyIEModel struct {
	ID          types.Int64 `tfsdk:"id"`
	DefaultDrop types.Bool  `tfsdk:"default_drop"`
	DropAmp     types.Bool  `tfsdk:"drop_amp"`
	RateLimit   types.Int64 `tfsdk:"rate_limit"`
}

// ServiceProtoIEModel represents a proto-ingress-egress service entry.
type ServiceProtoIEModel struct {
	ID          types.Int64 `tfsdk:"id"`
	Proto       types.Int64 `tfsdk:"proto"`
	DefaultDrop types.Bool  `tfsdk:"default_drop"`
	DropAmp     types.Bool  `tfsdk:"drop_amp"`
	RateLimit   types.Int64 `tfsdk:"rate_limit"`
}

// ServiceTCPIEModel represents a tcp-ingress-egress service entry.
type ServiceTCPIEModel struct {
	ID          types.Int64 `tfsdk:"id"`
	DefaultDrop types.Bool  `tfsdk:"default_drop"`
}

// ServiceTCPEModel represents a tcp-egress service entry.
type ServiceTCPEModel struct {
	ID          types.Int64 `tfsdk:"id"`
	DefaultDrop types.Bool  `tfsdk:"default_drop"`
}

// ServiceFragIEModel represents a frag-ingress-egress service entry.
type ServiceFragIEModel struct {
	ID          types.Int64 `tfsdk:"id"`
	DefaultDrop types.Bool  `tfsdk:"default_drop"`
	RateLimit   types.Int64 `tfsdk:"rate_limit"`
}
