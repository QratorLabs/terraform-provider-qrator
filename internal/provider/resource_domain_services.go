package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

var (
	_ resource.Resource                   = &DomainServicesResource{}
	_ resource.ResourceWithImportState    = &DomainServicesResource{}
	_ resource.ResourceWithValidateConfig = &DomainServicesResource{}
)

type DomainServicesResource struct {
	client *client.QratorClient
}

func NewDomainServicesResource() resource.Resource {
	return &DomainServicesResource{}
}

// ---------------------------------------------------------------------------
// API types
// ---------------------------------------------------------------------------

type apiServiceEntry struct {
	ID            *int64           `json:"id,omitempty"`
	Type          string           `json:"type"`
	Port          *int64           `json:"port,omitempty"`
	Proto         interface{}      `json:"proto,omitempty"`
	DefaultDrop   *bool            `json:"defaultDrop,omitempty"`
	DropAmp       *bool            `json:"dropAmp,omitempty"`
	RateLimit     *int64           `json:"rateLimit,omitempty"`
	SSL           *bool            `json:"ssl,omitempty"`
	HTTP2         *bool            `json:"http2,omitempty"`
	ProxyProtocol *int64           `json:"proxyProtocol,omitempty"`
	Upstream      *json.RawMessage `json:"upstream,omitempty"`
}

type apiUpstreamServer struct {
	IP        *string `json:"ip,omitempty"`
	DNSRecord *string `json:"dns_record,omitempty"`
	Port      int64   `json:"port"`
	Weight    int64   `json:"weight"`
	Type      string  `json:"type"`
	Name      string  `json:"name,omitempty"`
}

type apiHTTPUpstream struct {
	Balancer        string              `json:"balancer"`
	Weights         bool                `json:"weights"`
	Backups         bool                `json:"backups"`
	SSL             bool                `json:"ssl"`
	SNIName         *string             `json:"sniName,omitempty"`
	SNINameOverride *bool               `json:"sniNameOverride,omitempty"`
	Upstreams       []apiUpstreamServer `json:"upstreams"`
}

type apiNATUpstream struct {
	IP   string `json:"ip"`
	Port int64  `json:"port"`
}

type apiTCPProxyUpstream struct {
	Upstreams []apiUpstreamServer `json:"upstreams"`
}

type apiWebSocketUpstream struct {
	SSL       bool                `json:"ssl"`
	Upstreams []apiUpstreamServer `json:"upstreams"`
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func (r *DomainServicesResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_domain_services"
}

func (r *DomainServicesResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the service list for a domain in Qrator.",
		Attributes: map[string]schema.Attribute{
			"domain_id": schema.Int64Attribute{
				Description: "The domain ID.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"http": schema.ListNestedAttribute{
				Description: "HTTP service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: httpServiceSchemaAttrs(),
				},
			},
			"nat": schema.ListNestedAttribute{
				Description: "NAT (TCP/UDP) service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: natServiceSchemaAttrs(),
				},
			},
			"nat_all": schema.ListNestedAttribute{
				Description: "NAT-all (TCP/UDP, all ports) service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: natAllServiceSchemaAttrs(),
				},
			},
			"tcpproxy": schema.ListNestedAttribute{
				Description: "TCP proxy service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: tcpproxyServiceSchemaAttrs(),
				},
			},
			"websocket": schema.ListNestedAttribute{
				Description: "WebSocket service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: websocketServiceSchemaAttrs(),
				},
			},
		},
	}
}

func serviceIDAttr() schema.Int64Attribute {
	return schema.Int64Attribute{
		Description: "Service entry ID assigned by the API.",
		Computed:    true,
		PlanModifiers: []planmodifier.Int64{
			int64planmodifier.UseStateForUnknown(),
		},
	}
}

func httpServiceSchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id":   serviceIDAttr(),
		"port": portAttr(),
		"ssl": schema.BoolAttribute{
			Description: "Enable SSL/TLS on the frontend.",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"http2": schema.BoolAttribute{
			Description: "Enable HTTP/2.",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
		"upstream_balancer": schema.StringAttribute{
			Description: "Load balancing algorithm: roundrobin or iphash.",
			Required:    true,
			Validators:  []validator.String{stringvalidator.OneOf("roundrobin", "iphash")},
		},
		"upstream_weights": schema.BoolAttribute{
			Description: "Enable weight-based load balancing.",
			Required:    true,
		},
		"upstream_backups": schema.BoolAttribute{
			Description: "Enable backup server support.",
			Required:    true,
		},
		"upstream_ssl": schema.BoolAttribute{
			Description: "Enable SSL/TLS for upstream connections.",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"upstream_sni_name": schema.StringAttribute{
			Description: "SNI hostname for upstream TLS connections.",
			Optional:    true,
			Validators:  []validator.String{stringvalidator.LengthAtMost(255)},
		},
		"upstream_sni_override": schema.BoolAttribute{
			Description: "Force use of sni_name as HOST header in upstream request.",
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
		},
		"upstreams": schema.ListNestedAttribute{
			Description: "Upstream servers.",
			Required:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: upstreamServerAttrs(true),
			},
		},
	}
}

func natServiceSchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id":   serviceIDAttr(),
		"port": portAttr(),
		"proto": schema.StringAttribute{
			Description: "Protocol: tcp or udp.",
			Required:    true,
			Validators:  []validator.String{stringvalidator.OneOf("tcp", "udp")},
		},
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
		"drop_amp": schema.BoolAttribute{
			Description: "If true, amplified packets are dropped. Only for UDP.",
			Optional:    true,
		},
		"rate_limit": schema.Int64Attribute{
			Description: "Maximum packet rate (bps). Only for UDP. Must be between 8000 and 1000000000000, multiple of 8000.",
			Optional:    true,
			Validators:  []validator.Int64{int64validator.Between(8000, 1000000000000)},
		},
		"upstream_ip": schema.StringAttribute{
			Description: "Upstream server IPv4 address.",
			Required:    true,
		},
		"upstream_port": schema.Int64Attribute{
			Description: "Upstream server port (1-65535).",
			Required:    true,
			Validators:  []validator.Int64{int64validator.Between(1, 65535)},
		},
	}
}

func natAllServiceSchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": serviceIDAttr(),
		"proto": schema.StringAttribute{
			Description: "Protocol: tcp or udp.",
			Required:    true,
			Validators:  []validator.String{stringvalidator.OneOf("tcp", "udp")},
		},
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
		"drop_amp": schema.BoolAttribute{
			Description: "If true, amplified packets are dropped. Only for UDP.",
			Optional:    true,
		},
		"rate_limit": schema.Int64Attribute{
			Description: "Maximum packet rate (bps). Must be between 8000 and 1000000000000, multiple of 8000.",
			Optional:    true,
		},
		"upstream_ip": schema.StringAttribute{
			Description: "Upstream server IPv4 address.",
			Required:    true,
		},
	}
}

func tcpproxyServiceSchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id":   serviceIDAttr(),
		"port": portAttr(),
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
		"proxy_protocol": schema.Int64Attribute{
			Description: "Proxy protocol version: 0, 1, or 2.",
			Optional:    true,
			Validators:  []validator.Int64{int64validator.OneOf(0, 1, 2)},
		},
		"upstreams": schema.ListNestedAttribute{
			Description: "Upstream servers.",
			Required:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: upstreamServerAttrs(false),
			},
		},
	}
}

func websocketServiceSchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id":   serviceIDAttr(),
		"port": portAttr(),
		"ssl": schema.BoolAttribute{
			Description: "Enable SSL/TLS on the frontend.",
			Optional:    true,
		},
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
		"upstream_ssl": schema.BoolAttribute{
			Description: "Enable SSL/TLS for upstream connections.",
			Required:    true,
		},
		"upstreams": schema.ListNestedAttribute{
			Description: "Upstream servers.",
			Required:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: upstreamServerAttrs(true),
			},
		},
	}
}

func portAttr() schema.Int64Attribute {
	return schema.Int64Attribute{
		Description: "Port number (1-65535).",
		Required:    true,
		Validators:  []validator.Int64{int64validator.Between(1, 65535)},
	}
}

func upstreamServerAttrs(allowDNS bool) map[string]schema.Attribute {
	ipAttr := schema.StringAttribute{
		Description: "Server IPv4 address.",
	}
	if allowDNS {
		ipAttr.Optional = true
	} else {
		ipAttr.Required = true
	}
	attrs := map[string]schema.Attribute{
		"ip": ipAttr,
		"port": schema.Int64Attribute{
			Description: "Server port (1-65535).",
			Required:    true,
			Validators:  []validator.Int64{int64validator.Between(1, 65535)},
		},
		"weight": schema.Int64Attribute{
			Description: "Server weight (0-100).",
			Required:    true,
			Validators:  []validator.Int64{int64validator.Between(0, 100)},
		},
		"type": schema.StringAttribute{
			Description: "Server type: primary or backup.",
			Required:    true,
			Validators:  []validator.String{stringvalidator.OneOf("primary", "backup")},
		},
		"name": schema.StringAttribute{
			Description: "Server name (max 255 chars).",
			Optional:    true,
			Computed:    true,
			Validators:  []validator.String{stringvalidator.LengthAtMost(255)},
		},
	}
	if allowDNS {
		attrs["dns_record"] = schema.StringAttribute{
			Description: "DNS record (alternative to IP, min 4 chars).",
			Optional:    true,
			Validators:  []validator.String{stringvalidator.LengthAtLeast(4)},
		}
	}
	return attrs
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func (r *DomainServicesResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *DomainServicesResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data DomainServicesResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keys := make(map[string]bool)

	for i, h := range data.HTTP {
		if h.Port.IsUnknown() {
			continue
		}
		k := compositeKeyHTTP(h.Port.ValueInt64())
		if keys[k] {
			resp.Diagnostics.AddAttributeError(path.Root("http").AtListIndex(i),
				"Duplicate service", fmt.Sprintf("Duplicate HTTP service on port %d", h.Port.ValueInt64()))
		}
		keys[k] = true

		if !h.SSL.IsNull() && !h.HTTP2.IsNull() && !h.SSL.ValueBool() && h.HTTP2.ValueBool() {
			resp.Diagnostics.AddAttributeError(path.Root("http").AtListIndex(i).AtName("http2"),
				"Invalid http2 setting", "http2 cannot be enabled when ssl is false")
		}
	}

	for i, n := range data.NAT {
		if n.Port.IsUnknown() || n.Proto.IsUnknown() {
			continue
		}
		k := compositeKeyNAT(n.Proto.ValueString(), n.Port.ValueInt64())
		if keys[k] {
			resp.Diagnostics.AddAttributeError(path.Root("nat").AtListIndex(i),
				"Duplicate service", fmt.Sprintf("Duplicate NAT %s service on port %d", n.Proto.ValueString(), n.Port.ValueInt64()))
		}
		keys[k] = true
	}

	for i, n := range data.NATAll {
		if n.Proto.IsUnknown() {
			continue
		}
		k := compositeKeyNATAll(n.Proto.ValueString())
		if keys[k] {
			resp.Diagnostics.AddAttributeError(path.Root("nat_all").AtListIndex(i),
				"Duplicate service", fmt.Sprintf("Duplicate nat-all %s entry", n.Proto.ValueString()))
		}
		keys[k] = true
	}

	for i, t := range data.TCPProxy {
		if t.Port.IsUnknown() {
			continue
		}
		k := compositeKeyTCPProxy(t.Port.ValueInt64())
		if keys[k] {
			resp.Diagnostics.AddAttributeError(path.Root("tcpproxy").AtListIndex(i),
				"Duplicate service", fmt.Sprintf("Duplicate tcpproxy service on port %d", t.Port.ValueInt64()))
		}
		keys[k] = true
	}

	for i, w := range data.WebSocket {
		if w.Port.IsUnknown() {
			continue
		}
		k := compositeKeyWebSocket(w.Port.ValueInt64())
		if keys[k] {
			resp.Diagnostics.AddAttributeError(path.Root("websocket").AtListIndex(i),
				"Duplicate service", fmt.Sprintf("Duplicate websocket service on port %d", w.Port.ValueInt64()))
		}
		keys[k] = true
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func (r *DomainServicesResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected numeric domain ID")
		return
	}
	resp.State.SetAttribute(ctx, path.Root("domain_id"), id)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func (r *DomainServicesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan DomainServicesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := plan.DomainID.ValueInt64()
	apiPath := fmt.Sprintf("/request/domain/%d", domainID)

	entries := buildServiceList(&plan)
	if err := r.writeServices(ctx, apiPath, entries); err != nil {
		resp.Diagnostics.AddError("Failed to set services", err.Error())
		return
	}

	if err := r.readAndPopulate(ctx, domainID, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to read services after create", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *DomainServicesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state DomainServicesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readAndPopulate(ctx, state.DomainID.ValueInt64(), &state); err != nil {
		resp.Diagnostics.AddError("Failed to read services", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *DomainServicesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state DomainServicesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := plan.DomainID.ValueInt64()
	apiPath := fmt.Sprintf("/request/domain/%d", domainID)

	entries := buildServiceList(&plan)
	injectIDsFromState(entries, &state)
	if err := r.writeServices(ctx, apiPath, entries); err != nil {
		resp.Diagnostics.AddError("Failed to set services", err.Error())
		return
	}

	if err := r.readAndPopulate(ctx, domainID, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to read services after update", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func (r *DomainServicesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state DomainServicesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := fmt.Sprintf("/request/domain/%d", state.DomainID.ValueInt64())
	if err := r.writeServices(ctx, apiPath, []apiServiceEntry{}); err != nil {
		resp.Diagnostics.AddError("Failed to clear services on delete", err.Error())
		return
	}
}

// ---------------------------------------------------------------------------
// Helpers: API calls
// ---------------------------------------------------------------------------

func (r *DomainServicesResource) writeServices(ctx context.Context, apiPath string, entries []apiServiceEntry) error {
	result, err := r.client.MakeRequest(ctx, apiPath, "services_set", entries)
	if err != nil {
		return fmt.Errorf("services_set failed: %w", err)
	}
	if !checkSuccess(result) {
		return fmt.Errorf("services_set returned unexpected response: %s", string(result))
	}
	return nil
}

func checkSuccess(response json.RawMessage) bool {
	var s string
	if err := json.Unmarshal(response, &s); err == nil {
		return s == "Successful"
	}
	return false
}

func (r *DomainServicesResource) readAndPopulate(ctx context.Context, domainID int64, model *DomainServicesResourceModel) error {
	apiPath := fmt.Sprintf("/request/domain/%d", domainID)

	v, err := r.client.MakeRequest(ctx, apiPath, "services_get", nil)
	if err != nil {
		return fmt.Errorf("services_get failed: %w", err)
	}

	var services []apiServiceEntry
	if err := json.Unmarshal(v, &services); err != nil {
		return fmt.Errorf("failed to parse services response: %w", err)
	}

	model.DomainID = types.Int64Value(domainID)
	apiToServicesModel(services, model)

	tflog.Debug(ctx, fmt.Sprintf("Read domain %d services: %d entries", domainID, len(services)))
	return nil
}

// ---------------------------------------------------------------------------
// Helpers: Composite keys
// ---------------------------------------------------------------------------

func compositeKeyHTTP(port int64) string {
	return fmt.Sprintf("http:%d", port)
}

func compositeKeyNAT(proto string, port int64) string {
	return fmt.Sprintf("nat:%s:%d", proto, port)
}

func compositeKeyNATAll(proto string) string {
	return fmt.Sprintf("nat-all:%s", proto)
}

func compositeKeyTCPProxy(port int64) string {
	return fmt.Sprintf("tcpproxy:%d", port)
}

func compositeKeyWebSocket(port int64) string {
	return fmt.Sprintf("websocket:%d", port)
}

func compositeKeyFromAPI(entry *apiServiceEntry) string {
	switch entry.Type {
	case "http":
		return compositeKeyHTTP(ptrInt64(entry.Port))
	case "nat":
		proto, _ := entry.Proto.(string)
		return compositeKeyNAT(proto, ptrInt64(entry.Port))
	case "nat-all":
		proto, _ := entry.Proto.(string)
		return compositeKeyNATAll(proto)
	case "tcpproxy":
		return compositeKeyTCPProxy(ptrInt64(entry.Port))
	case "websocket":
		return compositeKeyWebSocket(ptrInt64(entry.Port))
	}
	return ""
}

// ---------------------------------------------------------------------------
// Helpers: build service list from plan
// ---------------------------------------------------------------------------

func buildServiceList(m *DomainServicesResourceModel) []apiServiceEntry {
	var entries []apiServiceEntry

	for i := range m.HTTP {
		entries = append(entries, httpModelToAPI(&m.HTTP[i]))
	}
	for i := range m.NAT {
		entries = append(entries, natModelToAPI(&m.NAT[i]))
	}
	for i := range m.NATAll {
		entries = append(entries, natAllModelToAPI(&m.NATAll[i]))
	}
	for i := range m.TCPProxy {
		entries = append(entries, tcpproxyModelToAPI(&m.TCPProxy[i]))
	}
	for i := range m.WebSocket {
		entries = append(entries, websocketModelToAPI(&m.WebSocket[i]))
	}

	return entries
}

func injectIDsFromState(entries []apiServiceEntry, state *DomainServicesResourceModel) {
	if state == nil {
		return
	}
	idMap := make(map[string]int64)

	for _, h := range state.HTTP {
		if !h.ID.IsNull() && !h.ID.IsUnknown() {
			idMap[compositeKeyHTTP(h.Port.ValueInt64())] = h.ID.ValueInt64()
		}
	}
	for _, n := range state.NAT {
		if !n.ID.IsNull() && !n.ID.IsUnknown() {
			idMap[compositeKeyNAT(n.Proto.ValueString(), n.Port.ValueInt64())] = n.ID.ValueInt64()
		}
	}
	for _, n := range state.NATAll {
		if !n.ID.IsNull() && !n.ID.IsUnknown() {
			idMap[compositeKeyNATAll(n.Proto.ValueString())] = n.ID.ValueInt64()
		}
	}
	for _, t := range state.TCPProxy {
		if !t.ID.IsNull() && !t.ID.IsUnknown() {
			idMap[compositeKeyTCPProxy(t.Port.ValueInt64())] = t.ID.ValueInt64()
		}
	}
	for _, w := range state.WebSocket {
		if !w.ID.IsNull() && !w.ID.IsUnknown() {
			idMap[compositeKeyWebSocket(w.Port.ValueInt64())] = w.ID.ValueInt64()
		}
	}

	for i := range entries {
		key := compositeKeyFromAPI(&entries[i])
		if id, ok := idMap[key]; ok {
			entries[i].ID = &id
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers: API → model conversion (Read)
// ---------------------------------------------------------------------------

func apiToServicesModel(entries []apiServiceEntry, m *DomainServicesResourceModel) {
	m.HTTP = nil
	m.NAT = nil
	m.NATAll = nil
	m.TCPProxy = nil
	m.WebSocket = nil

	for i := range entries {
		e := &entries[i]
		switch e.Type {
		case "http":
			m.HTTP = append(m.HTTP, apiToHTTPModel(e))
		case "nat":
			m.NAT = append(m.NAT, apiToNATModel(e))
		case "nat-all":
			m.NATAll = append(m.NATAll, apiToNATAllModel(e))
		case "tcpproxy":
			m.TCPProxy = append(m.TCPProxy, apiToTCPProxyModel(e))
		case "websocket":
			m.WebSocket = append(m.WebSocket, apiToWSModel(e))
		}
	}

	sort.Slice(m.HTTP, func(i, j int) bool {
		return m.HTTP[i].Port.ValueInt64() < m.HTTP[j].Port.ValueInt64()
	})
	sort.Slice(m.NAT, func(i, j int) bool {
		ki := compositeKeyNAT(m.NAT[i].Proto.ValueString(), m.NAT[i].Port.ValueInt64())
		kj := compositeKeyNAT(m.NAT[j].Proto.ValueString(), m.NAT[j].Port.ValueInt64())
		return ki < kj
	})
	sort.Slice(m.NATAll, func(i, j int) bool {
		return m.NATAll[i].Proto.ValueString() < m.NATAll[j].Proto.ValueString()
	})
	sort.Slice(m.TCPProxy, func(i, j int) bool {
		return m.TCPProxy[i].Port.ValueInt64() < m.TCPProxy[j].Port.ValueInt64()
	})
	sort.Slice(m.WebSocket, func(i, j int) bool {
		return m.WebSocket[i].Port.ValueInt64() < m.WebSocket[j].Port.ValueInt64()
	})
}

func apiToHTTPModel(e *apiServiceEntry) DomainServiceHTTPModel {
	m := DomainServiceHTTPModel{
		ID:          optionalInt64(e.ID),
		Port:        types.Int64Value(ptrInt64(e.Port)),
		SSL:         optionalBool(e.SSL),
		HTTP2:       optionalBool(e.HTTP2),
		DefaultDrop: optionalBool(e.DefaultDrop),
	}

	if e.Upstream != nil {
		var u apiHTTPUpstream
		if err := json.Unmarshal(*e.Upstream, &u); err == nil {
			m.UpstreamBalancer = types.StringValue(u.Balancer)
			m.UpstreamWeights = types.BoolValue(u.Weights)
			m.UpstreamBackups = types.BoolValue(u.Backups)
			m.UpstreamSSL = types.BoolValue(u.SSL)
			if u.SNIName != nil {
				m.UpstreamSNIName = types.StringValue(*u.SNIName)
			} else {
				m.UpstreamSNIName = types.StringNull()
			}
			if u.SNINameOverride != nil {
				m.UpstreamSNIOverride = types.BoolValue(*u.SNINameOverride)
			} else {
				m.UpstreamSNIOverride = types.BoolNull()
			}
			m.Upstreams = upstreamServersFromAPI(u.Upstreams)
		}
	}

	return m
}

func apiToNATModel(e *apiServiceEntry) DomainServiceNATModel {
	proto, _ := e.Proto.(string)
	m := DomainServiceNATModel{
		ID:          optionalInt64(e.ID),
		Port:        types.Int64Value(ptrInt64(e.Port)),
		Proto:       types.StringValue(proto),
		DefaultDrop: optionalBool(e.DefaultDrop),
		DropAmp:     optionalBool(e.DropAmp),
		RateLimit:   optionalInt64(e.RateLimit),
	}

	if e.Upstream != nil {
		var u apiNATUpstream
		if err := json.Unmarshal(*e.Upstream, &u); err == nil {
			m.UpstreamIP = types.StringValue(u.IP)
			m.UpstreamPort = types.Int64Value(u.Port)
		}
	}

	return m
}

func apiToNATAllModel(e *apiServiceEntry) DomainServiceNATAllModel {
	proto, _ := e.Proto.(string)
	m := DomainServiceNATAllModel{
		ID:          optionalInt64(e.ID),
		Proto:       types.StringValue(proto),
		DefaultDrop: optionalBool(e.DefaultDrop),
		DropAmp:     optionalBool(e.DropAmp),
		RateLimit:   optionalInt64(e.RateLimit),
	}

	if e.Upstream != nil {
		var ip string
		if err := json.Unmarshal(*e.Upstream, &ip); err == nil {
			m.UpstreamIP = types.StringValue(ip)
		}
	}

	return m
}

func apiToTCPProxyModel(e *apiServiceEntry) DomainServiceTCPProxyModel {
	m := DomainServiceTCPProxyModel{
		ID:            optionalInt64(e.ID),
		Port:          types.Int64Value(ptrInt64(e.Port)),
		DefaultDrop:   optionalBool(e.DefaultDrop),
		ProxyProtocol: optionalInt64(e.ProxyProtocol),
	}

	if e.Upstream != nil {
		var u apiTCPProxyUpstream
		if err := json.Unmarshal(*e.Upstream, &u); err == nil {
			m.Upstreams = upstreamServersFromAPI(u.Upstreams)
		}
	}

	return m
}

func apiToWSModel(e *apiServiceEntry) DomainServiceWSModel {
	m := DomainServiceWSModel{
		ID:          optionalInt64(e.ID),
		Port:        types.Int64Value(ptrInt64(e.Port)),
		SSL:         optionalBool(e.SSL),
		DefaultDrop: optionalBool(e.DefaultDrop),
	}

	if e.Upstream != nil {
		var u apiWebSocketUpstream
		if err := json.Unmarshal(*e.Upstream, &u); err == nil {
			m.UpstreamSSL = types.BoolValue(u.SSL)
			m.Upstreams = upstreamServersFromAPI(u.Upstreams)
		}
	}

	return m
}

// ---------------------------------------------------------------------------
// Helpers: model → API conversion (Create/Update)
// ---------------------------------------------------------------------------

func httpModelToAPI(m *DomainServiceHTTPModel) apiServiceEntry {
	e := apiServiceEntry{Type: "http"}
	p := m.Port.ValueInt64()
	e.Port = &p
	e.SSL = boolPtr(m.SSL)
	e.HTTP2 = boolPtr(m.HTTP2)
	e.DefaultDrop = boolPtr(m.DefaultDrop)

	u := apiHTTPUpstream{
		Balancer:  m.UpstreamBalancer.ValueString(),
		Weights:   m.UpstreamWeights.ValueBool(),
		Backups:   m.UpstreamBackups.ValueBool(),
		SSL:       m.UpstreamSSL.ValueBool(),
		Upstreams: upstreamServersToAPI(m.Upstreams),
	}
	if !m.UpstreamSNIName.IsNull() && !m.UpstreamSNIName.IsUnknown() {
		s := m.UpstreamSNIName.ValueString()
		u.SNIName = &s
	}
	if !m.UpstreamSNIOverride.IsNull() && !m.UpstreamSNIOverride.IsUnknown() {
		b := m.UpstreamSNIOverride.ValueBool()
		u.SNINameOverride = &b
	}

	raw, _ := json.Marshal(u)
	rawMsg := json.RawMessage(raw)
	e.Upstream = &rawMsg
	return e
}

func natModelToAPI(m *DomainServiceNATModel) apiServiceEntry {
	e := apiServiceEntry{Type: "nat"}
	p := m.Port.ValueInt64()
	e.Port = &p
	e.Proto = m.Proto.ValueString()
	e.DefaultDrop = boolPtr(m.DefaultDrop)
	e.DropAmp = boolPtr(m.DropAmp)
	if !m.RateLimit.IsNull() && !m.RateLimit.IsUnknown() {
		rl := m.RateLimit.ValueInt64()
		e.RateLimit = &rl
	}

	u := apiNATUpstream{
		IP:   m.UpstreamIP.ValueString(),
		Port: m.UpstreamPort.ValueInt64(),
	}
	raw, _ := json.Marshal(u)
	rawMsg := json.RawMessage(raw)
	e.Upstream = &rawMsg
	return e
}

func natAllModelToAPI(m *DomainServiceNATAllModel) apiServiceEntry {
	e := apiServiceEntry{Type: "nat-all"}
	e.Proto = m.Proto.ValueString()
	e.DefaultDrop = boolPtr(m.DefaultDrop)
	e.DropAmp = boolPtr(m.DropAmp)
	if !m.RateLimit.IsNull() && !m.RateLimit.IsUnknown() {
		rl := m.RateLimit.ValueInt64()
		e.RateLimit = &rl
	}

	ip := m.UpstreamIP.ValueString()
	raw, _ := json.Marshal(ip)
	rawMsg := json.RawMessage(raw)
	e.Upstream = &rawMsg
	return e
}

func tcpproxyModelToAPI(m *DomainServiceTCPProxyModel) apiServiceEntry {
	e := apiServiceEntry{Type: "tcpproxy"}
	p := m.Port.ValueInt64()
	e.Port = &p
	e.DefaultDrop = boolPtr(m.DefaultDrop)
	if !m.ProxyProtocol.IsNull() && !m.ProxyProtocol.IsUnknown() {
		pp := m.ProxyProtocol.ValueInt64()
		e.ProxyProtocol = &pp
	}

	u := apiTCPProxyUpstream{
		Upstreams: upstreamServersToAPI(m.Upstreams),
	}
	raw, _ := json.Marshal(u)
	rawMsg := json.RawMessage(raw)
	e.Upstream = &rawMsg
	return e
}

func websocketModelToAPI(m *DomainServiceWSModel) apiServiceEntry {
	e := apiServiceEntry{Type: "websocket"}
	p := m.Port.ValueInt64()
	e.Port = &p
	e.SSL = boolPtr(m.SSL)
	e.DefaultDrop = boolPtr(m.DefaultDrop)

	u := apiWebSocketUpstream{
		SSL:       m.UpstreamSSL.ValueBool(),
		Upstreams: upstreamServersToAPI(m.Upstreams),
	}
	raw, _ := json.Marshal(u)
	rawMsg := json.RawMessage(raw)
	e.Upstream = &rawMsg
	return e
}

// ---------------------------------------------------------------------------
// Helpers: upstream server conversion
// ---------------------------------------------------------------------------

func upstreamServersToAPI(models []DomainUpstreamServerModel) []apiUpstreamServer {
	servers := make([]apiUpstreamServer, len(models))
	for i, m := range models {
		s := apiUpstreamServer{
			Port:   m.Port.ValueInt64(),
			Weight: m.Weight.ValueInt64(),
			Type:   m.Type.ValueString(),
		}
		if !m.IP.IsNull() && !m.IP.IsUnknown() {
			ip := m.IP.ValueString()
			s.IP = &ip
		}
		if !m.DNSRecord.IsNull() && !m.DNSRecord.IsUnknown() {
			dns := m.DNSRecord.ValueString()
			s.DNSRecord = &dns
		}
		if !m.Name.IsNull() && !m.Name.IsUnknown() {
			s.Name = m.Name.ValueString()
		}
		servers[i] = s
	}
	return servers
}

func upstreamServersFromAPI(servers []apiUpstreamServer) []DomainUpstreamServerModel {
	models := make([]DomainUpstreamServerModel, len(servers))
	for i, s := range servers {
		m := DomainUpstreamServerModel{
			Port:   types.Int64Value(s.Port),
			Weight: types.Int64Value(s.Weight),
			Type:   types.StringValue(s.Type),
			Name:   types.StringValue(s.Name),
		}
		if s.IP != nil {
			m.IP = types.StringValue(*s.IP)
		} else {
			m.IP = types.StringNull()
		}
		if s.DNSRecord != nil {
			m.DNSRecord = types.StringValue(*s.DNSRecord)
		} else {
			m.DNSRecord = types.StringNull()
		}
		models[i] = m
	}
	return models
}

// ---------------------------------------------------------------------------
// Helpers: pointer utilities
// ---------------------------------------------------------------------------

func ptrInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func optionalInt64(p *int64) types.Int64 {
	if p == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*p)
}

func optionalBool(p *bool) types.Bool {
	if p == nil {
		return types.BoolNull()
	}
	return types.BoolValue(*p)
}

func boolPtr(v types.Bool) *bool {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	b := v.ValueBool()
	return &b
}
