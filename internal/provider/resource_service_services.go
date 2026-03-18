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
	_ resource.Resource                   = &ServiceServicesResource{}
	_ resource.ResourceWithImportState    = &ServiceServicesResource{}
	_ resource.ResourceWithModifyPlan     = &ServiceServicesResource{}
	_ resource.ResourceWithValidateConfig = &ServiceServicesResource{}
)

type ServiceServicesResource struct {
	client *client.QratorClient
}

func NewServiceServicesResource() resource.Resource {
	return &ServiceServicesResource{}
}

// ---------------------------------------------------------------------------
// API types (service-specific upstream)
// ---------------------------------------------------------------------------

type apiServiceHTTPUpstream struct {
	SSL             bool    `json:"ssl"`
	SNIName         *string `json:"sniName,omitempty"`
	SNINameOverride *bool   `json:"sniNameOverride,omitempty"`
}

// ---------------------------------------------------------------------------
// Metadata / Schema
// ---------------------------------------------------------------------------

func (r *ServiceServicesResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_services"
}

func (r *ServiceServicesResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the service list for a service in Qrator.",
		Attributes: map[string]schema.Attribute{
			"service_id": schema.Int64Attribute{
				Description: "The service ID.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"dns": schema.ListNestedAttribute{
				Description: "DNS service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: svcDNSSchemaAttrs(),
				},
			},
			"http": schema.ListNestedAttribute{
				Description: "HTTP service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: svcHTTPSchemaAttrs(),
				},
			},
			"icmp": schema.ListNestedAttribute{
				Description: "ICMP service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: svcICMPSchemaAttrs(),
				},
			},
			"nat": schema.ListNestedAttribute{
				Description: "NAT (TCP/UDP) service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: svcNATSchemaAttrs(),
				},
			},
			"any_ingress_egress": schema.ListNestedAttribute{
				Description: "Any-ingress-egress service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: svcAnyIESchemaAttrs(),
				},
			},
			"proto_ingress_egress": schema.ListNestedAttribute{
				Description: "Proto-ingress-egress service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: svcProtoIESchemaAttrs(),
				},
			},
			"tcp_ingress_egress": schema.ListNestedAttribute{
				Description: "TCP-ingress-egress service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: svcTCPIESchemaAttrs(),
				},
			},
			"tcp_egress": schema.ListNestedAttribute{
				Description: "TCP-egress service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: svcTCPEgressSchemaAttrs(),
				},
			},
			"frag_ingress_egress": schema.ListNestedAttribute{
				Description: "Frag-ingress-egress service entries.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: svcFragIESchemaAttrs(),
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Schema attribute helpers
// ---------------------------------------------------------------------------

func svcDNSSchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id":   serviceIDAttr(),
		"port": portAttr(),
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
	}
}

func svcHTTPSchemaAttrs() map[string]schema.Attribute {
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
		"upstream": schema.SingleNestedAttribute{
			Description: "Upstream connection settings.",
			Required:    true,
			Attributes: map[string]schema.Attribute{
				"ssl": schema.BoolAttribute{
					Description: "Enable SSL/TLS for upstream connections.",
					Required:    true,
				},
				"sni_name": schema.StringAttribute{
					Description: "SNI hostname for upstream TLS connections.",
					Optional:    true,
					Validators:  []validator.String{stringvalidator.LengthAtMost(255)},
				},
				"sni_override": schema.BoolAttribute{
					Description: "Force use of sni_name as HOST header in upstream request.",
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(false),
				},
			},
		},
	}
}

func svcICMPSchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": serviceIDAttr(),
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
		"rate_limit": rateLimitAttr(),
	}
}

func svcNATSchemaAttrs() map[string]schema.Attribute {
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
		"rate_limit": rateLimitAttr(),
	}
}

func svcAnyIESchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": serviceIDAttr(),
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
		"drop_amp": schema.BoolAttribute{
			Description: "If true, amplified packets are dropped.",
			Optional:    true,
		},
		"rate_limit": rateLimitAttr(),
	}
}

func svcProtoIESchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": serviceIDAttr(),
		"proto": schema.Int64Attribute{
			Description: "IP protocol number (1-254).",
			Required:    true,
			Validators:  []validator.Int64{int64validator.Between(1, 254)},
		},
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
		"drop_amp": schema.BoolAttribute{
			Description: "If true, amplified packets are dropped.",
			Optional:    true,
		},
		"rate_limit": rateLimitAttr(),
	}
}

func svcTCPIESchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": serviceIDAttr(),
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
	}
}

func svcTCPEgressSchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": serviceIDAttr(),
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
	}
}

func svcFragIESchemaAttrs() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": serviceIDAttr(),
		"default_drop": schema.BoolAttribute{
			Description: "If true, only whitelisted IPs can access the service.",
			Optional:    true,
			Computed:    true,
		},
		"rate_limit": rateLimitAttr(),
	}
}

func rateLimitAttr() schema.Int64Attribute {
	return schema.Int64Attribute{
		Description: "Maximum packet rate (bps). Must be between 8000 and 1000000000000, multiple of 8000.",
		Optional:    true,
		Validators:  []validator.Int64{int64validator.Between(8000, 1000000000000)},
	}
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func (r *ServiceServicesResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ServiceServicesResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var dnsList, httpList, icmpList, natList, anyIEList, protoIEList, tcpIEList, tcpEList, fragIEList types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("dns"), &dnsList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("http"), &httpList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("icmp"), &icmpList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("nat"), &natList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("any_ingress_egress"), &anyIEList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("proto_ingress_egress"), &protoIEList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("tcp_ingress_egress"), &tcpIEList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("tcp_egress"), &tcpEList)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("frag_ingress_egress"), &fragIEList)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keys := make(map[string]bool)

	if !dnsList.IsUnknown() && !dnsList.IsNull() {
		var dns []ServiceDNSModel
		resp.Diagnostics.Append(dnsList.ElementsAs(ctx, &dns, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for i, d := range dns {
			if d.Port.IsUnknown() {
				continue
			}
			k := fmt.Sprintf("dns:%d", d.Port.ValueInt64())
			if keys[k] {
				resp.Diagnostics.AddAttributeError(path.Root("dns").AtListIndex(i),
					"Duplicate service", fmt.Sprintf("Duplicate DNS service on port %d", d.Port.ValueInt64()))
			}
			keys[k] = true
		}
	}

	if !httpList.IsUnknown() && !httpList.IsNull() {
		var http []ServiceHTTPModel
		resp.Diagnostics.Append(httpList.ElementsAs(ctx, &http, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for i, h := range http {
			if h.Port.IsUnknown() {
				continue
			}
			k := fmt.Sprintf("http:%d", h.Port.ValueInt64())
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

	if !icmpList.IsUnknown() && !icmpList.IsNull() {
		var icmp []ServiceICMPModel
		resp.Diagnostics.Append(icmpList.ElementsAs(ctx, &icmp, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(icmp) > 1 {
			resp.Diagnostics.AddAttributeError(path.Root("icmp"),
				"Too many ICMP entries", "At most one ICMP service entry is allowed")
		}
	}

	if !natList.IsUnknown() && !natList.IsNull() {
		var nat []ServiceNATModel
		resp.Diagnostics.Append(natList.ElementsAs(ctx, &nat, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for i, n := range nat {
			if n.Port.IsUnknown() || n.Proto.IsUnknown() {
				continue
			}
			k := fmt.Sprintf("nat:%s:%d", n.Proto.ValueString(), n.Port.ValueInt64())
			if keys[k] {
				resp.Diagnostics.AddAttributeError(path.Root("nat").AtListIndex(i),
					"Duplicate service", fmt.Sprintf("Duplicate NAT %s service on port %d", n.Proto.ValueString(), n.Port.ValueInt64()))
			}
			keys[k] = true
		}
	}

	if !anyIEList.IsUnknown() && !anyIEList.IsNull() {
		var anyIE []ServiceAnyIEModel
		resp.Diagnostics.Append(anyIEList.ElementsAs(ctx, &anyIE, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(anyIE) > 1 {
			resp.Diagnostics.AddAttributeError(path.Root("any_ingress_egress"),
				"Too many entries", "At most one any-ingress-egress service entry is allowed")
		}
	}

	if !protoIEList.IsUnknown() && !protoIEList.IsNull() {
		var protoIE []ServiceProtoIEModel
		resp.Diagnostics.Append(protoIEList.ElementsAs(ctx, &protoIE, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for i, p := range protoIE {
			if p.Proto.IsUnknown() {
				continue
			}
			k := fmt.Sprintf("proto-ie:%d", p.Proto.ValueInt64())
			if keys[k] {
				resp.Diagnostics.AddAttributeError(path.Root("proto_ingress_egress").AtListIndex(i),
					"Duplicate service", fmt.Sprintf("Duplicate proto-ingress-egress service for proto %d", p.Proto.ValueInt64()))
			}
			keys[k] = true
		}
	}

	if !tcpIEList.IsUnknown() && !tcpIEList.IsNull() {
		var tcpIE []ServiceTCPIEModel
		resp.Diagnostics.Append(tcpIEList.ElementsAs(ctx, &tcpIE, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(tcpIE) > 1 {
			resp.Diagnostics.AddAttributeError(path.Root("tcp_ingress_egress"),
				"Too many entries", "At most one tcp-ingress-egress service entry is allowed")
		}
	}

	if !tcpEList.IsUnknown() && !tcpEList.IsNull() {
		var tcpE []ServiceTCPEModel
		resp.Diagnostics.Append(tcpEList.ElementsAs(ctx, &tcpE, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(tcpE) > 1 {
			resp.Diagnostics.AddAttributeError(path.Root("tcp_egress"),
				"Too many entries", "At most one tcp-egress service entry is allowed")
		}
	}

	if !fragIEList.IsUnknown() && !fragIEList.IsNull() {
		var fragIE []ServiceFragIEModel
		resp.Diagnostics.Append(fragIEList.ElementsAs(ctx, &fragIE, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if len(fragIE) > 1 {
			resp.Diagnostics.AddAttributeError(path.Root("frag_ingress_egress"),
				"Too many entries", "At most one frag-ingress-egress service entry is allowed")
		}
	}
}

// ---------------------------------------------------------------------------
// ModifyPlan — match service entry IDs by composite key, not list index
// ---------------------------------------------------------------------------

func (r *ServiceServicesResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Destroy or create — nothing to match.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	// Load state lists (always known — state values are never unknown).
	var stateDNS, stateHTTP, stateICMP, stateNAT, stateAnyIE, stateProtoIE, stateTCPIE, stateTCPE, stateFragIE types.List
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("dns"), &stateDNS)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("http"), &stateHTTP)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("icmp"), &stateICMP)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("nat"), &stateNAT)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("any_ingress_egress"), &stateAnyIE)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("proto_ingress_egress"), &stateProtoIE)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("tcp_ingress_egress"), &stateTCPIE)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("tcp_egress"), &stateTCPE)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("frag_ingress_egress"), &stateFragIE)...)

	// Load plan lists (may be unknown when referencing not-yet-computed values).
	var planDNS, planHTTP, planICMP, planNAT, planAnyIE, planProtoIE, planTCPIE, planTCPE, planFragIE types.List
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("dns"), &planDNS)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("http"), &planHTTP)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("icmp"), &planICMP)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("nat"), &planNAT)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("any_ingress_egress"), &planAnyIE)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("proto_ingress_egress"), &planProtoIE)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("tcp_ingress_egress"), &planTCPIE)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("tcp_egress"), &planTCPE)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("frag_ingress_egress"), &planFragIE)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Build composite-key → ID map from state.
	idByKey := make(map[string]int64)

	if !stateDNS.IsNull() {
		var dns []ServiceDNSModel
		resp.Diagnostics.Append(stateDNS.ElementsAs(ctx, &dns, false)...)
		for i := range dns {
			if !dns[i].ID.IsNull() && !dns[i].ID.IsUnknown() {
				idByKey[fmt.Sprintf("dns:%d", dns[i].Port.ValueInt64())] = dns[i].ID.ValueInt64()
			}
		}
	}
	if !stateHTTP.IsNull() {
		var http []ServiceHTTPModel
		resp.Diagnostics.Append(stateHTTP.ElementsAs(ctx, &http, false)...)
		for i := range http {
			if !http[i].ID.IsNull() && !http[i].ID.IsUnknown() {
				idByKey[fmt.Sprintf("http:%d", http[i].Port.ValueInt64())] = http[i].ID.ValueInt64()
			}
		}
	}
	if !stateICMP.IsNull() {
		var icmp []ServiceICMPModel
		resp.Diagnostics.Append(stateICMP.ElementsAs(ctx, &icmp, false)...)
		for i := range icmp {
			if !icmp[i].ID.IsNull() && !icmp[i].ID.IsUnknown() {
				idByKey["icmp"] = icmp[i].ID.ValueInt64()
			}
		}
	}
	if !stateNAT.IsNull() {
		var nat []ServiceNATModel
		resp.Diagnostics.Append(stateNAT.ElementsAs(ctx, &nat, false)...)
		for i := range nat {
			if !nat[i].ID.IsNull() && !nat[i].ID.IsUnknown() {
				idByKey[fmt.Sprintf("nat:%s:%d", nat[i].Proto.ValueString(), nat[i].Port.ValueInt64())] = nat[i].ID.ValueInt64()
			}
		}
	}
	if !stateAnyIE.IsNull() {
		var anyIE []ServiceAnyIEModel
		resp.Diagnostics.Append(stateAnyIE.ElementsAs(ctx, &anyIE, false)...)
		for i := range anyIE {
			if !anyIE[i].ID.IsNull() && !anyIE[i].ID.IsUnknown() {
				idByKey["any-ingress-egress"] = anyIE[i].ID.ValueInt64()
			}
		}
	}
	if !stateProtoIE.IsNull() {
		var protoIE []ServiceProtoIEModel
		resp.Diagnostics.Append(stateProtoIE.ElementsAs(ctx, &protoIE, false)...)
		for i := range protoIE {
			if !protoIE[i].ID.IsNull() && !protoIE[i].ID.IsUnknown() {
				idByKey[fmt.Sprintf("proto-ie:%d", protoIE[i].Proto.ValueInt64())] = protoIE[i].ID.ValueInt64()
			}
		}
	}
	if !stateTCPIE.IsNull() {
		var tcpIE []ServiceTCPIEModel
		resp.Diagnostics.Append(stateTCPIE.ElementsAs(ctx, &tcpIE, false)...)
		for i := range tcpIE {
			if !tcpIE[i].ID.IsNull() && !tcpIE[i].ID.IsUnknown() {
				idByKey["tcp-ingress-egress"] = tcpIE[i].ID.ValueInt64()
			}
		}
	}
	if !stateTCPE.IsNull() {
		var tcpE []ServiceTCPEModel
		resp.Diagnostics.Append(stateTCPE.ElementsAs(ctx, &tcpE, false)...)
		for i := range tcpE {
			if !tcpE[i].ID.IsNull() && !tcpE[i].ID.IsUnknown() {
				idByKey["tcp-egress"] = tcpE[i].ID.ValueInt64()
			}
		}
	}
	if !stateFragIE.IsNull() {
		var fragIE []ServiceFragIEModel
		resp.Diagnostics.Append(stateFragIE.ElementsAs(ctx, &fragIE, false)...)
		for i := range fragIE {
			if !fragIE[i].ID.IsNull() && !fragIE[i].ID.IsUnknown() {
				idByKey["frag-ingress-egress"] = fragIE[i].ID.ValueInt64()
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

	if !planDNS.IsUnknown() && !planDNS.IsNull() {
		var dns []ServiceDNSModel
		resp.Diagnostics.Append(planDNS.ElementsAs(ctx, &dns, false)...)
		for i := range dns {
			assignID(&dns[i].ID, fmt.Sprintf("dns:%d", dns[i].Port.ValueInt64()))
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("dns"), dns)...)
	}
	if !planHTTP.IsUnknown() && !planHTTP.IsNull() {
		var http []ServiceHTTPModel
		resp.Diagnostics.Append(planHTTP.ElementsAs(ctx, &http, false)...)
		for i := range http {
			assignID(&http[i].ID, fmt.Sprintf("http:%d", http[i].Port.ValueInt64()))
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("http"), http)...)
	}
	if !planICMP.IsUnknown() && !planICMP.IsNull() {
		var icmp []ServiceICMPModel
		resp.Diagnostics.Append(planICMP.ElementsAs(ctx, &icmp, false)...)
		for i := range icmp {
			assignID(&icmp[i].ID, "icmp")
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("icmp"), icmp)...)
	}
	if !planNAT.IsUnknown() && !planNAT.IsNull() {
		var nat []ServiceNATModel
		resp.Diagnostics.Append(planNAT.ElementsAs(ctx, &nat, false)...)
		for i := range nat {
			assignID(&nat[i].ID, fmt.Sprintf("nat:%s:%d", nat[i].Proto.ValueString(), nat[i].Port.ValueInt64()))
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("nat"), nat)...)
	}
	if !planAnyIE.IsUnknown() && !planAnyIE.IsNull() {
		var anyIE []ServiceAnyIEModel
		resp.Diagnostics.Append(planAnyIE.ElementsAs(ctx, &anyIE, false)...)
		for i := range anyIE {
			assignID(&anyIE[i].ID, "any-ingress-egress")
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("any_ingress_egress"), anyIE)...)
	}
	if !planProtoIE.IsUnknown() && !planProtoIE.IsNull() {
		var protoIE []ServiceProtoIEModel
		resp.Diagnostics.Append(planProtoIE.ElementsAs(ctx, &protoIE, false)...)
		for i := range protoIE {
			assignID(&protoIE[i].ID, fmt.Sprintf("proto-ie:%d", protoIE[i].Proto.ValueInt64()))
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("proto_ingress_egress"), protoIE)...)
	}
	if !planTCPIE.IsUnknown() && !planTCPIE.IsNull() {
		var tcpIE []ServiceTCPIEModel
		resp.Diagnostics.Append(planTCPIE.ElementsAs(ctx, &tcpIE, false)...)
		for i := range tcpIE {
			assignID(&tcpIE[i].ID, "tcp-ingress-egress")
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("tcp_ingress_egress"), tcpIE)...)
	}
	if !planTCPE.IsUnknown() && !planTCPE.IsNull() {
		var tcpE []ServiceTCPEModel
		resp.Diagnostics.Append(planTCPE.ElementsAs(ctx, &tcpE, false)...)
		for i := range tcpE {
			assignID(&tcpE[i].ID, "tcp-egress")
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("tcp_egress"), tcpE)...)
	}
	if !planFragIE.IsUnknown() && !planFragIE.IsNull() {
		var fragIE []ServiceFragIEModel
		resp.Diagnostics.Append(planFragIE.ElementsAs(ctx, &fragIE, false)...)
		for i := range fragIE {
			assignID(&fragIE[i].ID, "frag-ingress-egress")
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("frag_ingress_egress"), fragIE)...)
	}
}

// ---------------------------------------------------------------------------
// ImportState
// ---------------------------------------------------------------------------

func (r *ServiceServicesResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected numeric service ID")
		return
	}
	resp.State.SetAttribute(ctx, path.Root("service_id"), id)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func (r *ServiceServicesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ServiceServicesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Remember plan order and which fields were explicitly set (empty list) vs null.
	planDNS, planHTTP, planICMP := plan.DNS, plan.HTTP, plan.ICMP
	planNAT, planAnyIE, planProtoIE := plan.NAT, plan.AnyIngressEgress, plan.ProtoIngressEgress
	planTCPIE, planTCPE, planFragIE := plan.TCPIngressEgress, plan.TCPEgress, plan.FragIngressEgress
	set := svcListsSet(&plan)

	serviceID := plan.ServiceID.ValueInt64()
	apiPath := entityService.apiPath(serviceID)

	entries := buildSvcServiceList(&plan)
	if err := r.writeServices(ctx, apiPath, entries); err != nil {
		resp.Diagnostics.AddError("Failed to set services", err.Error())
		return
	}

	if err := r.readAndPopulate(ctx, serviceID, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to read services after create", err.Error())
		return
	}

	// On first apply IDs were unknown so plan kept config order; reorder state to match.
	plan.DNS = reorderByPlanOrder(planDNS, plan.DNS, func(e *ServiceDNSModel) string { return fmt.Sprintf("dns:%d", e.Port.ValueInt64()) })
	plan.HTTP = reorderByPlanOrder(planHTTP, plan.HTTP, func(e *ServiceHTTPModel) string { return fmt.Sprintf("http:%d", e.Port.ValueInt64()) })
	plan.ICMP = reorderByPlanOrder(planICMP, plan.ICMP, func(e *ServiceICMPModel) string { return "icmp" })
	plan.NAT = reorderByPlanOrder(planNAT, plan.NAT, func(e *ServiceNATModel) string { return fmt.Sprintf("nat:%s:%d", e.Proto.ValueString(), e.Port.ValueInt64()) })
	plan.AnyIngressEgress = reorderByPlanOrder(planAnyIE, plan.AnyIngressEgress, func(e *ServiceAnyIEModel) string { return "any-ingress-egress" })
	plan.ProtoIngressEgress = reorderByPlanOrder(planProtoIE, plan.ProtoIngressEgress, func(e *ServiceProtoIEModel) string { return fmt.Sprintf("proto-ie:%d", e.Proto.ValueInt64()) })
	plan.TCPIngressEgress = reorderByPlanOrder(planTCPIE, plan.TCPIngressEgress, func(e *ServiceTCPIEModel) string { return "tcp-ingress-egress" })
	plan.TCPEgress = reorderByPlanOrder(planTCPE, plan.TCPEgress, func(e *ServiceTCPEModel) string { return "tcp-egress" })
	plan.FragIngressEgress = reorderByPlanOrder(planFragIE, plan.FragIngressEgress, func(e *ServiceFragIEModel) string { return "frag-ingress-egress" })

	// Restore empty-list vs null: API returning nothing must not turn [] into null.
	preserveSvcEmptySlices(&plan, set)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *ServiceServicesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ServiceServicesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	prevDNS, prevHTTP, prevICMP := state.DNS, state.HTTP, state.ICMP
	prevNAT, prevAnyIE, prevProtoIE := state.NAT, state.AnyIngressEgress, state.ProtoIngressEgress
	prevTCPIE, prevTCPE, prevFragIE := state.TCPIngressEgress, state.TCPEgress, state.FragIngressEgress
	set := svcListsSet(&state)

	if err := r.readAndPopulate(ctx, state.ServiceID.ValueInt64(), &state); err != nil {
		resp.Diagnostics.AddError("Failed to read services", err.Error())
		return
	}

	state.DNS = reorderByPlanOrder(prevDNS, state.DNS, func(e *ServiceDNSModel) string { return fmt.Sprintf("dns:%d", e.Port.ValueInt64()) })
	state.HTTP = reorderByPlanOrder(prevHTTP, state.HTTP, func(e *ServiceHTTPModel) string { return fmt.Sprintf("http:%d", e.Port.ValueInt64()) })
	state.ICMP = reorderByPlanOrder(prevICMP, state.ICMP, func(e *ServiceICMPModel) string { return "icmp" })
	state.NAT = reorderByPlanOrder(prevNAT, state.NAT, func(e *ServiceNATModel) string { return fmt.Sprintf("nat:%s:%d", e.Proto.ValueString(), e.Port.ValueInt64()) })
	state.AnyIngressEgress = reorderByPlanOrder(prevAnyIE, state.AnyIngressEgress, func(e *ServiceAnyIEModel) string { return "any-ingress-egress" })
	state.ProtoIngressEgress = reorderByPlanOrder(prevProtoIE, state.ProtoIngressEgress, func(e *ServiceProtoIEModel) string { return fmt.Sprintf("proto-ie:%d", e.Proto.ValueInt64()) })
	state.TCPIngressEgress = reorderByPlanOrder(prevTCPIE, state.TCPIngressEgress, func(e *ServiceTCPIEModel) string { return "tcp-ingress-egress" })
	state.TCPEgress = reorderByPlanOrder(prevTCPE, state.TCPEgress, func(e *ServiceTCPEModel) string { return "tcp-egress" })
	state.FragIngressEgress = reorderByPlanOrder(prevFragIE, state.FragIngressEgress, func(e *ServiceFragIEModel) string { return "frag-ingress-egress" })

	preserveSvcEmptySlices(&state, set)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *ServiceServicesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ServiceServicesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planDNS, planHTTP, planICMP := plan.DNS, plan.HTTP, plan.ICMP
	planNAT, planAnyIE, planProtoIE := plan.NAT, plan.AnyIngressEgress, plan.ProtoIngressEgress
	planTCPIE, planTCPE, planFragIE := plan.TCPIngressEgress, plan.TCPEgress, plan.FragIngressEgress
	set := svcListsSet(&plan)

	serviceID := plan.ServiceID.ValueInt64()
	apiPath := entityService.apiPath(serviceID)

	entries := buildSvcServiceList(&plan)
	injectSvcIDsFromState(entries, &state)
	if err := r.writeServices(ctx, apiPath, entries); err != nil {
		resp.Diagnostics.AddError("Failed to set services", err.Error())
		return
	}

	if err := r.readAndPopulate(ctx, serviceID, &plan); err != nil {
		resp.Diagnostics.AddError("Failed to read services after update", err.Error())
		return
	}

	plan.DNS = reorderByPlanOrder(planDNS, plan.DNS, func(e *ServiceDNSModel) string { return fmt.Sprintf("dns:%d", e.Port.ValueInt64()) })
	plan.HTTP = reorderByPlanOrder(planHTTP, plan.HTTP, func(e *ServiceHTTPModel) string { return fmt.Sprintf("http:%d", e.Port.ValueInt64()) })
	plan.ICMP = reorderByPlanOrder(planICMP, plan.ICMP, func(e *ServiceICMPModel) string { return "icmp" })
	plan.NAT = reorderByPlanOrder(planNAT, plan.NAT, func(e *ServiceNATModel) string { return fmt.Sprintf("nat:%s:%d", e.Proto.ValueString(), e.Port.ValueInt64()) })
	plan.AnyIngressEgress = reorderByPlanOrder(planAnyIE, plan.AnyIngressEgress, func(e *ServiceAnyIEModel) string { return "any-ingress-egress" })
	plan.ProtoIngressEgress = reorderByPlanOrder(planProtoIE, plan.ProtoIngressEgress, func(e *ServiceProtoIEModel) string { return fmt.Sprintf("proto-ie:%d", e.Proto.ValueInt64()) })
	plan.TCPIngressEgress = reorderByPlanOrder(planTCPIE, plan.TCPIngressEgress, func(e *ServiceTCPIEModel) string { return "tcp-ingress-egress" })
	plan.TCPEgress = reorderByPlanOrder(planTCPE, plan.TCPEgress, func(e *ServiceTCPEModel) string { return "tcp-egress" })
	plan.FragIngressEgress = reorderByPlanOrder(planFragIE, plan.FragIngressEgress, func(e *ServiceFragIEModel) string { return "frag-ingress-egress" })

	preserveSvcEmptySlices(&plan, set)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func (r *ServiceServicesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ServiceServicesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := entityService.apiPath(state.ServiceID.ValueInt64())
	if err := r.writeServices(ctx, apiPath, []apiServiceEntry{}); err != nil {
		resp.Diagnostics.AddError("Failed to clear services on delete", err.Error())
		return
	}
}

// ---------------------------------------------------------------------------
// Helpers: API calls
// ---------------------------------------------------------------------------

func (r *ServiceServicesResource) writeServices(ctx context.Context, apiPath string, entries []apiServiceEntry) error {
	result, err := r.client.MakeRequest(ctx, apiPath, "services_set", entries)
	if err != nil {
		return fmt.Errorf("services_set failed: %w", err)
	}
	if !checkSuccess(result) {
		return fmt.Errorf("services_set returned unexpected response: %s", string(result))
	}
	return nil
}

func (r *ServiceServicesResource) readAndPopulate(ctx context.Context, serviceID int64, model *ServiceServicesResourceModel) error {
	apiPath := entityService.apiPath(serviceID)

	v, err := r.client.MakeRequest(ctx, apiPath, "services_get", nil)
	if err != nil {
		return fmt.Errorf("services_get failed: %w", err)
	}

	var services []apiServiceEntry
	if err := json.Unmarshal(v, &services); err != nil {
		return fmt.Errorf("failed to parse services response: %w", err)
	}

	model.ServiceID = types.Int64Value(serviceID)
	apiToSvcServicesModel(services, model)

	tflog.Debug(ctx, fmt.Sprintf("Read service %d services: %d entries", serviceID, len(services)))
	return nil
}

// ---------------------------------------------------------------------------
// Helpers: Composite keys
// ---------------------------------------------------------------------------

func svcCompositeKey(entry *apiServiceEntry) string {
	switch entry.Type {
	case "dns":
		return fmt.Sprintf("dns:%d", ptrInt64(entry.Port))
	case "http":
		return fmt.Sprintf("http:%d", ptrInt64(entry.Port))
	case "icmp":
		return "icmp"
	case "nat":
		proto, _ := entry.Proto.(string)
		return fmt.Sprintf("nat:%s:%d", proto, ptrInt64(entry.Port))
	case "any-ingress-egress":
		return "any-ingress-egress"
	case "proto-ingress-egress":
		var proto int64
		switch v := entry.Proto.(type) {
		case float64:
			proto = int64(v)
		case int64:
			proto = v
		}
		return fmt.Sprintf("proto-ingress-egress:%d", proto)
	case "tcp-ingress-egress":
		return "tcp-ingress-egress"
	case "tcp-egress":
		return "tcp-egress"
	case "frag-ingress-egress":
		return "frag-ingress-egress"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Helpers: build service list from plan
// ---------------------------------------------------------------------------

func buildSvcServiceList(m *ServiceServicesResourceModel) []apiServiceEntry {
	var entries []apiServiceEntry

	for i := range m.DNS {
		entries = append(entries, svcDNSModelToAPI(&m.DNS[i]))
	}
	for i := range m.HTTP {
		entries = append(entries, svcHTTPModelToAPI(&m.HTTP[i]))
	}
	for i := range m.ICMP {
		entries = append(entries, svcICMPModelToAPI(&m.ICMP[i]))
	}
	for i := range m.NAT {
		entries = append(entries, svcNATModelToAPI(&m.NAT[i]))
	}
	for i := range m.AnyIngressEgress {
		entries = append(entries, svcAnyIEModelToAPI(&m.AnyIngressEgress[i]))
	}
	for i := range m.ProtoIngressEgress {
		entries = append(entries, svcProtoIEModelToAPI(&m.ProtoIngressEgress[i]))
	}
	for i := range m.TCPIngressEgress {
		entries = append(entries, svcTCPIEModelToAPI(&m.TCPIngressEgress[i]))
	}
	for i := range m.TCPEgress {
		entries = append(entries, svcTCPEgressModelToAPI(&m.TCPEgress[i]))
	}
	for i := range m.FragIngressEgress {
		entries = append(entries, svcFragIEModelToAPI(&m.FragIngressEgress[i]))
	}

	return entries
}

func injectSvcIDsFromState(entries []apiServiceEntry, state *ServiceServicesResourceModel) {
	if state == nil {
		return
	}
	idMap := make(map[string]int64)

	for _, d := range state.DNS {
		if !d.ID.IsNull() && !d.ID.IsUnknown() {
			idMap[fmt.Sprintf("dns:%d", d.Port.ValueInt64())] = d.ID.ValueInt64()
		}
	}
	for _, h := range state.HTTP {
		if !h.ID.IsNull() && !h.ID.IsUnknown() {
			idMap[fmt.Sprintf("http:%d", h.Port.ValueInt64())] = h.ID.ValueInt64()
		}
	}
	for _, ic := range state.ICMP {
		if !ic.ID.IsNull() && !ic.ID.IsUnknown() {
			idMap["icmp"] = ic.ID.ValueInt64()
		}
	}
	for _, n := range state.NAT {
		if !n.ID.IsNull() && !n.ID.IsUnknown() {
			idMap[fmt.Sprintf("nat:%s:%d", n.Proto.ValueString(), n.Port.ValueInt64())] = n.ID.ValueInt64()
		}
	}
	for _, a := range state.AnyIngressEgress {
		if !a.ID.IsNull() && !a.ID.IsUnknown() {
			idMap["any-ingress-egress"] = a.ID.ValueInt64()
		}
	}
	for _, p := range state.ProtoIngressEgress {
		if !p.ID.IsNull() && !p.ID.IsUnknown() {
			idMap[fmt.Sprintf("proto-ingress-egress:%d", p.Proto.ValueInt64())] = p.ID.ValueInt64()
		}
	}
	for _, t := range state.TCPIngressEgress {
		if !t.ID.IsNull() && !t.ID.IsUnknown() {
			idMap["tcp-ingress-egress"] = t.ID.ValueInt64()
		}
	}
	for _, t := range state.TCPEgress {
		if !t.ID.IsNull() && !t.ID.IsUnknown() {
			idMap["tcp-egress"] = t.ID.ValueInt64()
		}
	}
	for _, f := range state.FragIngressEgress {
		if !f.ID.IsNull() && !f.ID.IsUnknown() {
			idMap["frag-ingress-egress"] = f.ID.ValueInt64()
		}
	}

	for i := range entries {
		key := svcCompositeKey(&entries[i])
		if id, ok := idMap[key]; ok {
			entries[i].ID = &id
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers: API → model conversion (Read)
// ---------------------------------------------------------------------------

func apiToSvcServicesModel(entries []apiServiceEntry, m *ServiceServicesResourceModel) {
	m.DNS = nil
	m.HTTP = nil
	m.ICMP = nil
	m.NAT = nil
	m.AnyIngressEgress = nil
	m.ProtoIngressEgress = nil
	m.TCPIngressEgress = nil
	m.TCPEgress = nil
	m.FragIngressEgress = nil

	for i := range entries {
		e := &entries[i]
		switch e.Type {
		case "dns":
			m.DNS = append(m.DNS, apiToSvcDNSModel(e))
		case "http":
			m.HTTP = append(m.HTTP, apiToSvcHTTPModel(e))
		case "icmp":
			m.ICMP = append(m.ICMP, apiToSvcICMPModel(e))
		case "nat":
			m.NAT = append(m.NAT, apiToSvcNATModel(e))
		case "any-ingress-egress":
			m.AnyIngressEgress = append(m.AnyIngressEgress, apiToSvcAnyIEModel(e))
		case "proto-ingress-egress":
			m.ProtoIngressEgress = append(m.ProtoIngressEgress, apiToSvcProtoIEModel(e))
		case "tcp-ingress-egress":
			m.TCPIngressEgress = append(m.TCPIngressEgress, apiToSvcTCPIEModel(e))
		case "tcp-egress":
			m.TCPEgress = append(m.TCPEgress, apiToSvcTCPEgressModel(e))
		case "frag-ingress-egress":
			m.FragIngressEgress = append(m.FragIngressEgress, apiToSvcFragIEModel(e))
		}
	}

	// Sort each type by API-assigned ID for stable, deterministic order.
	sortByID(m.DNS, func(e *ServiceDNSModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.HTTP, func(e *ServiceHTTPModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.ICMP, func(e *ServiceICMPModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.NAT, func(e *ServiceNATModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.AnyIngressEgress, func(e *ServiceAnyIEModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.ProtoIngressEgress, func(e *ServiceProtoIEModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.TCPIngressEgress, func(e *ServiceTCPIEModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.TCPEgress, func(e *ServiceTCPEModel) int64 { return e.ID.ValueInt64() })
	sortByID(m.FragIngressEgress, func(e *ServiceFragIEModel) int64 { return e.ID.ValueInt64() })
}

func sortByID[T any](s []T, id func(*T) int64) {
	sort.SliceStable(s, func(i, j int) bool {
		return id(&s[i]) < id(&s[j])
	})
}


func apiToSvcDNSModel(e *apiServiceEntry) ServiceDNSModel {
	return ServiceDNSModel{
		ID:          optionalInt64(e.ID),
		Port:        types.Int64Value(ptrInt64(e.Port)),
		DefaultDrop: optionalBool(e.DefaultDrop),
	}
}

func apiToSvcHTTPModel(e *apiServiceEntry) ServiceHTTPModel {
	m := ServiceHTTPModel{
		ID:          optionalInt64(e.ID),
		Port:        types.Int64Value(ptrInt64(e.Port)),
		SSL:         optionalBool(e.SSL),
		HTTP2:       optionalBool(e.HTTP2),
		DefaultDrop: optionalBool(e.DefaultDrop),
	}

	if e.Upstream != nil {
		var u apiServiceHTTPUpstream
		if err := json.Unmarshal(*e.Upstream, &u); err == nil {
			up := &ServiceHTTPUpstreamModel{
				SSL: types.BoolValue(u.SSL),
			}
			if u.SNIName != nil {
				up.SNIName = types.StringValue(*u.SNIName)
			} else {
				up.SNIName = types.StringNull()
			}
			if u.SNINameOverride != nil {
				up.SNIOverride = types.BoolValue(*u.SNINameOverride)
			} else {
				up.SNIOverride = types.BoolNull()
			}
			m.Upstream = up
		}
	}

	return m
}

func apiToSvcICMPModel(e *apiServiceEntry) ServiceICMPModel {
	return ServiceICMPModel{
		ID:          optionalInt64(e.ID),
		DefaultDrop: optionalBool(e.DefaultDrop),
		RateLimit:   optionalInt64(e.RateLimit),
	}
}

func apiToSvcNATModel(e *apiServiceEntry) ServiceNATModel {
	proto, _ := e.Proto.(string)
	return ServiceNATModel{
		ID:          optionalInt64(e.ID),
		Port:        types.Int64Value(ptrInt64(e.Port)),
		Proto:       types.StringValue(proto),
		DefaultDrop: optionalBool(e.DefaultDrop),
		DropAmp:     optionalBool(e.DropAmp),
		RateLimit:   optionalInt64(e.RateLimit),
	}
}

func apiToSvcAnyIEModel(e *apiServiceEntry) ServiceAnyIEModel {
	return ServiceAnyIEModel{
		ID:          optionalInt64(e.ID),
		DefaultDrop: optionalBool(e.DefaultDrop),
		DropAmp:     optionalBool(e.DropAmp),
		RateLimit:   optionalInt64(e.RateLimit),
	}
}

func apiToSvcProtoIEModel(e *apiServiceEntry) ServiceProtoIEModel {
	var proto int64
	switch v := e.Proto.(type) {
	case float64:
		proto = int64(v)
	case int64:
		proto = v
	}
	return ServiceProtoIEModel{
		ID:          optionalInt64(e.ID),
		Proto:       types.Int64Value(proto),
		DefaultDrop: optionalBool(e.DefaultDrop),
		DropAmp:     optionalBool(e.DropAmp),
		RateLimit:   optionalInt64(e.RateLimit),
	}
}

func apiToSvcTCPIEModel(e *apiServiceEntry) ServiceTCPIEModel {
	return ServiceTCPIEModel{
		ID:          optionalInt64(e.ID),
		DefaultDrop: optionalBool(e.DefaultDrop),
	}
}

func apiToSvcTCPEgressModel(e *apiServiceEntry) ServiceTCPEModel {
	return ServiceTCPEModel{
		ID:          optionalInt64(e.ID),
		DefaultDrop: optionalBool(e.DefaultDrop),
	}
}

func apiToSvcFragIEModel(e *apiServiceEntry) ServiceFragIEModel {
	return ServiceFragIEModel{
		ID:          optionalInt64(e.ID),
		DefaultDrop: optionalBool(e.DefaultDrop),
		RateLimit:   optionalInt64(e.RateLimit),
	}
}

// ---------------------------------------------------------------------------
// Helpers: model → API conversion (Create/Update)
// ---------------------------------------------------------------------------

func svcDNSModelToAPI(m *ServiceDNSModel) apiServiceEntry {
	e := apiServiceEntry{Type: "dns"}
	p := m.Port.ValueInt64()
	e.Port = &p
	e.DefaultDrop = boolPtr(m.DefaultDrop)
	return e
}

func svcHTTPModelToAPI(m *ServiceHTTPModel) apiServiceEntry {
	e := apiServiceEntry{Type: "http"}
	p := m.Port.ValueInt64()
	e.Port = &p
	e.SSL = boolPtr(m.SSL)
	e.HTTP2 = boolPtr(m.HTTP2)
	e.DefaultDrop = boolPtr(m.DefaultDrop)

	u := apiServiceHTTPUpstream{
		SSL: m.Upstream.SSL.ValueBool(),
	}
	if !m.Upstream.SNIName.IsNull() && !m.Upstream.SNIName.IsUnknown() {
		s := m.Upstream.SNIName.ValueString()
		u.SNIName = &s
	}
	if !m.Upstream.SNIOverride.IsNull() && !m.Upstream.SNIOverride.IsUnknown() {
		b := m.Upstream.SNIOverride.ValueBool()
		u.SNINameOverride = &b
	}

	raw, _ := json.Marshal(u)
	rawMsg := json.RawMessage(raw)
	e.Upstream = &rawMsg
	return e
}

func svcICMPModelToAPI(m *ServiceICMPModel) apiServiceEntry {
	e := apiServiceEntry{Type: "icmp"}
	e.DefaultDrop = boolPtr(m.DefaultDrop)
	if !m.RateLimit.IsNull() && !m.RateLimit.IsUnknown() {
		rl := m.RateLimit.ValueInt64()
		e.RateLimit = &rl
	}
	return e
}

func svcNATModelToAPI(m *ServiceNATModel) apiServiceEntry {
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
	return e
}

func svcAnyIEModelToAPI(m *ServiceAnyIEModel) apiServiceEntry {
	e := apiServiceEntry{Type: "any-ingress-egress"}
	e.DefaultDrop = boolPtr(m.DefaultDrop)
	e.DropAmp = boolPtr(m.DropAmp)
	if !m.RateLimit.IsNull() && !m.RateLimit.IsUnknown() {
		rl := m.RateLimit.ValueInt64()
		e.RateLimit = &rl
	}
	return e
}

func svcProtoIEModelToAPI(m *ServiceProtoIEModel) apiServiceEntry {
	e := apiServiceEntry{Type: "proto-ingress-egress"}
	p := m.Proto.ValueInt64()
	e.Proto = p
	e.DefaultDrop = boolPtr(m.DefaultDrop)
	e.DropAmp = boolPtr(m.DropAmp)
	if !m.RateLimit.IsNull() && !m.RateLimit.IsUnknown() {
		rl := m.RateLimit.ValueInt64()
		e.RateLimit = &rl
	}
	return e
}

func svcTCPIEModelToAPI(m *ServiceTCPIEModel) apiServiceEntry {
	e := apiServiceEntry{Type: "tcp-ingress-egress"}
	e.DefaultDrop = boolPtr(m.DefaultDrop)
	return e
}

func svcTCPEgressModelToAPI(m *ServiceTCPEModel) apiServiceEntry {
	e := apiServiceEntry{Type: "tcp-egress"}
	e.DefaultDrop = boolPtr(m.DefaultDrop)
	return e
}

func svcFragIEModelToAPI(m *ServiceFragIEModel) apiServiceEntry {
	e := apiServiceEntry{Type: "frag-ingress-egress"}
	e.DefaultDrop = boolPtr(m.DefaultDrop)
	if !m.RateLimit.IsNull() && !m.RateLimit.IsUnknown() {
		rl := m.RateLimit.ValueInt64()
		e.RateLimit = &rl
	}
	return e
}

// svcListsSet captures which list fields are non-nil (explicitly set vs null).
type svcListsSetFlags struct {
	dns, http, icmp, nat, anyIE, protoIE, tcpIE, tcpE, fragIE bool
}

func svcListsSet(m *ServiceServicesResourceModel) svcListsSetFlags {
	return svcListsSetFlags{
		dns:     m.DNS != nil,
		http:    m.HTTP != nil,
		icmp:    m.ICMP != nil,
		nat:     m.NAT != nil,
		anyIE:   m.AnyIngressEgress != nil,
		protoIE: m.ProtoIngressEgress != nil,
		tcpIE:   m.TCPIngressEgress != nil,
		tcpE:    m.TCPEgress != nil,
		fragIE:  m.FragIngressEgress != nil,
	}
}

// preserveSvcEmptySlices restores empty-list (vs nil/null) for service list
// fields that were explicitly set in config but returned no entries from API.
func preserveSvcEmptySlices(m *ServiceServicesResourceModel, s svcListsSetFlags) {
	if s.dns && m.DNS == nil {
		m.DNS = []ServiceDNSModel{}
	}
	if s.http && m.HTTP == nil {
		m.HTTP = []ServiceHTTPModel{}
	}
	if s.icmp && m.ICMP == nil {
		m.ICMP = []ServiceICMPModel{}
	}
	if s.nat && m.NAT == nil {
		m.NAT = []ServiceNATModel{}
	}
	if s.anyIE && m.AnyIngressEgress == nil {
		m.AnyIngressEgress = []ServiceAnyIEModel{}
	}
	if s.protoIE && m.ProtoIngressEgress == nil {
		m.ProtoIngressEgress = []ServiceProtoIEModel{}
	}
	if s.tcpIE && m.TCPIngressEgress == nil {
		m.TCPIngressEgress = []ServiceTCPIEModel{}
	}
	if s.tcpE && m.TCPEgress == nil {
		m.TCPEgress = []ServiceTCPEModel{}
	}
	if s.fragIE && m.FragIngressEgress == nil {
		m.FragIngressEgress = []ServiceFragIEModel{}
	}
}
