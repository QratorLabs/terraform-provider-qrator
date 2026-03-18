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
	_ resource.ResourceWithModifyPlan     = &DomainServicesResource{}
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
			computedUnknownInt64{},
		},
	}
}

// computedUnknownInt64 ensures a Computed-only attribute is Unknown (not null)
// in the plan when the user hasn't set it. Works around terraform-plugin-framework
// not always promoting null to Unknown for Computed attributes inside
// ListNestedAttribute elements.
type computedUnknownInt64 struct{}

func (m computedUnknownInt64) Description(_ context.Context) string {
	return "Sets null to unknown for computed attributes."
}

func (m computedUnknownInt64) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m computedUnknownInt64) PlanModifyInt64(_ context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	if req.ConfigValue.IsNull() && resp.PlanValue.IsNull() {
		resp.PlanValue = types.Int64Unknown()
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
				Attributes: upstreamServerAttrs(),
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
				Attributes: upstreamServerAttrs(),
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
				Attributes: upstreamServerAttrs(),
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

func upstreamServerAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"ip": schema.StringAttribute{
			Description: "Server IPv4 address. Either ip or dns_record must be set.",
			Optional:    true,
		},
		"dns_record": schema.StringAttribute{
			Description: "DNS record (alternative to ip, min 4 chars).",
			Optional:    true,
			Validators:  []validator.String{stringvalidator.LengthAtLeast(4)},
		},
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
	var httpList, natList, natAllList, tcpList, wsList types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("http"), &httpList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("nat"), &natList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("nat_all"), &natAllList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("tcpproxy"), &tcpList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("websocket"), &wsList)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keys := make(map[string]bool)

	if !httpList.IsUnknown() && !httpList.IsNull() {
		var http []DomainServiceHTTPModel
		resp.Diagnostics.Append(httpList.ElementsAs(ctx, &http, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for i, h := range http {
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
	}

	if !natList.IsUnknown() && !natList.IsNull() {
		var nat []DomainServiceNATModel
		resp.Diagnostics.Append(natList.ElementsAs(ctx, &nat, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for i, n := range nat {
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
	}

	if !natAllList.IsUnknown() && !natAllList.IsNull() {
		var natAll []DomainServiceNATAllModel
		resp.Diagnostics.Append(natAllList.ElementsAs(ctx, &natAll, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for i, n := range natAll {
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
	}

	if !tcpList.IsUnknown() && !tcpList.IsNull() {
		var tcp []DomainServiceTCPProxyModel
		resp.Diagnostics.Append(tcpList.ElementsAs(ctx, &tcp, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for i, t := range tcp {
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
	}

	if !wsList.IsUnknown() && !wsList.IsNull() {
		var ws []DomainServiceWSModel
		resp.Diagnostics.Append(wsList.ElementsAs(ctx, &ws, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for i, w := range ws {
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
}

// ---------------------------------------------------------------------------
// ModifyPlan — match service entry IDs by composite key, not list index
// ---------------------------------------------------------------------------

func (r *DomainServicesResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	// Load state lists (always known — state values are never unknown).
	var stateHTTP, stateNAT, stateNATAll, stateTCPProxy, stateWS types.List
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("http"), &stateHTTP)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("nat"), &stateNAT)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("nat_all"), &stateNATAll)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("tcpproxy"), &stateTCPProxy)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("websocket"), &stateWS)...)

	// Load plan lists (may be unknown when referencing not-yet-computed values).
	var planHTTP, planNAT, planNATAll, planTCPProxy, planWS types.List
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("http"), &planHTTP)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("nat"), &planNAT)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("nat_all"), &planNATAll)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("tcpproxy"), &planTCPProxy)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("websocket"), &planWS)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Build composite-key → ID map from state.
	idByKey := make(map[string]int64)

	if !stateHTTP.IsNull() {
		var http []DomainServiceHTTPModel
		resp.Diagnostics.Append(stateHTTP.ElementsAs(ctx, &http, false)...)
		for i := range http {
			if !http[i].ID.IsNull() && !http[i].ID.IsUnknown() {
				idByKey[compositeKeyHTTP(http[i].Port.ValueInt64())] = http[i].ID.ValueInt64()
			}
		}
	}
	if !stateNAT.IsNull() {
		var nat []DomainServiceNATModel
		resp.Diagnostics.Append(stateNAT.ElementsAs(ctx, &nat, false)...)
		for i := range nat {
			if !nat[i].ID.IsNull() && !nat[i].ID.IsUnknown() {
				idByKey[compositeKeyNAT(nat[i].Proto.ValueString(), nat[i].Port.ValueInt64())] = nat[i].ID.ValueInt64()
			}
		}
	}
	if !stateNATAll.IsNull() {
		var natAll []DomainServiceNATAllModel
		resp.Diagnostics.Append(stateNATAll.ElementsAs(ctx, &natAll, false)...)
		for i := range natAll {
			if !natAll[i].ID.IsNull() && !natAll[i].ID.IsUnknown() {
				idByKey[compositeKeyNATAll(natAll[i].Proto.ValueString())] = natAll[i].ID.ValueInt64()
			}
		}
	}
	if !stateTCPProxy.IsNull() {
		var tcp []DomainServiceTCPProxyModel
		resp.Diagnostics.Append(stateTCPProxy.ElementsAs(ctx, &tcp, false)...)
		for i := range tcp {
			if !tcp[i].ID.IsNull() && !tcp[i].ID.IsUnknown() {
				idByKey[compositeKeyTCPProxy(tcp[i].Port.ValueInt64())] = tcp[i].ID.ValueInt64()
			}
		}
	}
	if !stateWS.IsNull() {
		var ws []DomainServiceWSModel
		resp.Diagnostics.Append(stateWS.ElementsAs(ctx, &ws, false)...)
		for i := range ws {
			if !ws[i].ID.IsNull() && !ws[i].ID.IsUnknown() {
				idByKey[compositeKeyWebSocket(ws[i].Port.ValueInt64())] = ws[i].ID.ValueInt64()
			}
		}
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Assign correct IDs to plan entries by composite key.
	// Skip unknown lists — they stay unknown in the plan.
	assignID := func(id *types.Int64, key string) {
		if v, ok := idByKey[key]; ok {
			*id = types.Int64Value(v)
		} else {
			*id = types.Int64Unknown()
		}
	}

	if !planHTTP.IsUnknown() && !planHTTP.IsNull() {
		var http []DomainServiceHTTPModel
		resp.Diagnostics.Append(planHTTP.ElementsAs(ctx, &http, false)...)
		for i := range http {
			assignID(&http[i].ID, compositeKeyHTTP(http[i].Port.ValueInt64()))
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("http"), http)...)
	}
	if !planNAT.IsUnknown() && !planNAT.IsNull() {
		var nat []DomainServiceNATModel
		resp.Diagnostics.Append(planNAT.ElementsAs(ctx, &nat, false)...)
		for i := range nat {
			assignID(&nat[i].ID, compositeKeyNAT(nat[i].Proto.ValueString(), nat[i].Port.ValueInt64()))
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("nat"), nat)...)
	}
	if !planNATAll.IsUnknown() && !planNATAll.IsNull() {
		var natAll []DomainServiceNATAllModel
		resp.Diagnostics.Append(planNATAll.ElementsAs(ctx, &natAll, false)...)
		for i := range natAll {
			assignID(&natAll[i].ID, compositeKeyNATAll(natAll[i].Proto.ValueString()))
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("nat_all"), natAll)...)
	}
	if !planTCPProxy.IsUnknown() && !planTCPProxy.IsNull() {
		var tcp []DomainServiceTCPProxyModel
		resp.Diagnostics.Append(planTCPProxy.ElementsAs(ctx, &tcp, false)...)
		for i := range tcp {
			assignID(&tcp[i].ID, compositeKeyTCPProxy(tcp[i].Port.ValueInt64()))
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("tcpproxy"), tcp)...)
	}
	if !planWS.IsUnknown() && !planWS.IsNull() {
		var ws []DomainServiceWSModel
		resp.Diagnostics.Append(planWS.ElementsAs(ctx, &ws, false)...)
		for i := range ws {
			assignID(&ws[i].ID, compositeKeyWebSocket(ws[i].Port.ValueInt64()))
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("websocket"), ws)...)
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

	// Remember plan order and which fields were explicitly set (empty list) vs null.
	planHTTP, planNAT, planNATAll, planTCPProxy, planWS := plan.HTTP, plan.NAT, plan.NATAll, plan.TCPProxy, plan.WebSocket
	set := domainListsSet(&plan)

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

	// On first apply IDs were unknown so plan kept config order; reorder state to match.
	plan.HTTP = reorderByPlanOrder(planHTTP, plan.HTTP, func(e *DomainServiceHTTPModel) string { return compositeKeyHTTP(e.Port.ValueInt64()) })
	plan.NAT = reorderByPlanOrder(planNAT, plan.NAT, func(e *DomainServiceNATModel) string { return compositeKeyNAT(e.Proto.ValueString(), e.Port.ValueInt64()) })
	plan.NATAll = reorderByPlanOrder(planNATAll, plan.NATAll, func(e *DomainServiceNATAllModel) string { return compositeKeyNATAll(e.Proto.ValueString()) })
	plan.TCPProxy = reorderByPlanOrder(planTCPProxy, plan.TCPProxy, func(e *DomainServiceTCPProxyModel) string { return compositeKeyTCPProxy(e.Port.ValueInt64()) })
	plan.WebSocket = reorderByPlanOrder(planWS, plan.WebSocket, func(e *DomainServiceWSModel) string { return compositeKeyWebSocket(e.Port.ValueInt64()) })

	// Restore empty-list vs null: API returning nothing must not turn [] into null.
	preserveEmptySlices(&plan, set)

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

	prevHTTP, prevNAT, prevNATAll, prevTCPProxy, prevWS := state.HTTP, state.NAT, state.NATAll, state.TCPProxy, state.WebSocket
	set := domainListsSet(&state)

	if err := r.readAndPopulate(ctx, state.DomainID.ValueInt64(), &state); err != nil {
		resp.Diagnostics.AddError("Failed to read services", err.Error())
		return
	}

	state.HTTP = reorderByPlanOrder(prevHTTP, state.HTTP, func(e *DomainServiceHTTPModel) string { return compositeKeyHTTP(e.Port.ValueInt64()) })
	state.NAT = reorderByPlanOrder(prevNAT, state.NAT, func(e *DomainServiceNATModel) string { return compositeKeyNAT(e.Proto.ValueString(), e.Port.ValueInt64()) })
	state.NATAll = reorderByPlanOrder(prevNATAll, state.NATAll, func(e *DomainServiceNATAllModel) string { return compositeKeyNATAll(e.Proto.ValueString()) })
	state.TCPProxy = reorderByPlanOrder(prevTCPProxy, state.TCPProxy, func(e *DomainServiceTCPProxyModel) string { return compositeKeyTCPProxy(e.Port.ValueInt64()) })
	state.WebSocket = reorderByPlanOrder(prevWS, state.WebSocket, func(e *DomainServiceWSModel) string { return compositeKeyWebSocket(e.Port.ValueInt64()) })

	preserveEmptySlices(&state, set)

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

	planHTTP, planNAT, planNATAll, planTCPProxy, planWS := plan.HTTP, plan.NAT, plan.NATAll, plan.TCPProxy, plan.WebSocket
	set := domainListsSet(&plan)

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

	plan.HTTP = reorderByPlanOrder(planHTTP, plan.HTTP, func(e *DomainServiceHTTPModel) string { return compositeKeyHTTP(e.Port.ValueInt64()) })
	plan.NAT = reorderByPlanOrder(planNAT, plan.NAT, func(e *DomainServiceNATModel) string { return compositeKeyNAT(e.Proto.ValueString(), e.Port.ValueInt64()) })
	plan.NATAll = reorderByPlanOrder(planNATAll, plan.NATAll, func(e *DomainServiceNATAllModel) string { return compositeKeyNATAll(e.Proto.ValueString()) })
	plan.TCPProxy = reorderByPlanOrder(planTCPProxy, plan.TCPProxy, func(e *DomainServiceTCPProxyModel) string { return compositeKeyTCPProxy(e.Port.ValueInt64()) })
	plan.WebSocket = reorderByPlanOrder(planWS, plan.WebSocket, func(e *DomainServiceWSModel) string { return compositeKeyWebSocket(e.Port.ValueInt64()) })

	preserveEmptySlices(&plan, set)

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

	// Sort each type by API-assigned ID for stable, deterministic order.
	sortByID(m.HTTP, func(e *DomainServiceHTTPModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.NAT, func(e *DomainServiceNATModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.NATAll, func(e *DomainServiceNATAllModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.TCPProxy, func(e *DomainServiceTCPProxyModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.WebSocket, func(e *DomainServiceWSModel) int64 { return e.ID.ValueInt64() })
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

// reorderByPlanOrder reorders apiList to match the composite-key order of planList.
// Entries present in apiList but absent from planList are appended at the end.
// Used after Create so state order matches plan order on first apply.
func reorderByPlanOrder[T any](planList, apiList []T, key func(*T) string) []T {
	if len(apiList) == 0 {
		return apiList
	}
	byKey := make(map[string]T, len(apiList))
	for i := range apiList {
		byKey[key(&apiList[i])] = apiList[i]
	}
	result := make([]T, 0, len(apiList))
	seen := make(map[string]bool, len(apiList))
	for i := range planList {
		k := key(&planList[i])
		if e, ok := byKey[k]; ok {
			result = append(result, e)
			seen[k] = true
		}
	}
	for i := range apiList {
		if k := key(&apiList[i]); !seen[k] {
			result = append(result, apiList[i])
		}
	}
	return result
}

// preserveEmptySlices restores empty-slice (vs nil/null) for list fields that
// were explicitly set in the config but returned no entries from the API.
// Without this, a plan with tcpproxy=[] would become tcpproxy=null in state,
// causing a "Provider produced inconsistent result after apply" error.
type domainListsSetFlags struct {
	http, nat, natAll, tcp, ws bool
}

func domainListsSet(m *DomainServicesResourceModel) domainListsSetFlags {
	return domainListsSetFlags{
		http:   m.HTTP != nil,
		nat:    m.NAT != nil,
		natAll: m.NATAll != nil,
		tcp:    m.TCPProxy != nil,
		ws:     m.WebSocket != nil,
	}
}

func preserveEmptySlices(m *DomainServicesResourceModel, s domainListsSetFlags) {
	if s.http && m.HTTP == nil {
		m.HTTP = []DomainServiceHTTPModel{}
	}
	if s.nat && m.NAT == nil {
		m.NAT = []DomainServiceNATModel{}
	}
	if s.natAll && m.NATAll == nil {
		m.NATAll = []DomainServiceNATAllModel{}
	}
	if s.tcp && m.TCPProxy == nil {
		m.TCPProxy = []DomainServiceTCPProxyModel{}
	}
	if s.ws && m.WebSocket == nil {
		m.WebSocket = []DomainServiceWSModel{}
	}
}
