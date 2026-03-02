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
		"upstream_ssl": schema.BoolAttribute{
			Description: "Enable SSL/TLS for upstream connections.",
			Required:    true,
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
	var data ServiceServicesResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keys := make(map[string]bool)

	for i, d := range data.DNS {
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

	for i, h := range data.HTTP {
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

	if len(data.ICMP) > 1 {
		resp.Diagnostics.AddAttributeError(path.Root("icmp"),
			"Too many ICMP entries", "At most one ICMP service entry is allowed")
	}

	for i, n := range data.NAT {
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

	if len(data.AnyIngressEgress) > 1 {
		resp.Diagnostics.AddAttributeError(path.Root("any_ingress_egress"),
			"Too many entries", "At most one any-ingress-egress service entry is allowed")
	}

	for i, p := range data.ProtoIngressEgress {
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

	if len(data.TCPIngressEgress) > 1 {
		resp.Diagnostics.AddAttributeError(path.Root("tcp_ingress_egress"),
			"Too many entries", "At most one tcp-ingress-egress service entry is allowed")
	}

	if len(data.TCPEgress) > 1 {
		resp.Diagnostics.AddAttributeError(path.Root("tcp_egress"),
			"Too many entries", "At most one tcp-egress service entry is allowed")
	}

	if len(data.FragIngressEgress) > 1 {
		resp.Diagnostics.AddAttributeError(path.Root("frag_ingress_egress"),
			"Too many entries", "At most one frag-ingress-egress service entry is allowed")
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

	var plan, state ServiceServicesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build composite-key → ID map from state.
	idByKey := make(map[string]int64)
	for i := range state.DNS {
		e := &state.DNS[i]
		if !e.ID.IsNull() && !e.ID.IsUnknown() {
			idByKey[fmt.Sprintf("dns:%d", e.Port.ValueInt64())] = e.ID.ValueInt64()
		}
	}
	for i := range state.HTTP {
		e := &state.HTTP[i]
		if !e.ID.IsNull() && !e.ID.IsUnknown() {
			idByKey[fmt.Sprintf("http:%d", e.Port.ValueInt64())] = e.ID.ValueInt64()
		}
	}
	for i := range state.ICMP {
		e := &state.ICMP[i]
		if !e.ID.IsNull() && !e.ID.IsUnknown() {
			idByKey["icmp"] = e.ID.ValueInt64()
		}
	}
	for i := range state.NAT {
		e := &state.NAT[i]
		if !e.ID.IsNull() && !e.ID.IsUnknown() {
			idByKey[fmt.Sprintf("nat:%s:%d", e.Proto.ValueString(), e.Port.ValueInt64())] = e.ID.ValueInt64()
		}
	}
	for i := range state.AnyIngressEgress {
		e := &state.AnyIngressEgress[i]
		if !e.ID.IsNull() && !e.ID.IsUnknown() {
			idByKey["any-ingress-egress"] = e.ID.ValueInt64()
		}
	}
	for i := range state.ProtoIngressEgress {
		e := &state.ProtoIngressEgress[i]
		if !e.ID.IsNull() && !e.ID.IsUnknown() {
			idByKey[fmt.Sprintf("proto-ie:%d", e.Proto.ValueInt64())] = e.ID.ValueInt64()
		}
	}
	for i := range state.TCPIngressEgress {
		e := &state.TCPIngressEgress[i]
		if !e.ID.IsNull() && !e.ID.IsUnknown() {
			idByKey["tcp-ingress-egress"] = e.ID.ValueInt64()
		}
	}
	for i := range state.TCPEgress {
		e := &state.TCPEgress[i]
		if !e.ID.IsNull() && !e.ID.IsUnknown() {
			idByKey["tcp-egress"] = e.ID.ValueInt64()
		}
	}
	for i := range state.FragIngressEgress {
		e := &state.FragIngressEgress[i]
		if !e.ID.IsNull() && !e.ID.IsUnknown() {
			idByKey["frag-ingress-egress"] = e.ID.ValueInt64()
		}
	}

	// Assign correct IDs to plan entries by composite key.
	assignID := func(id *types.Int64, key string) {
		if v, ok := idByKey[key]; ok {
			*id = types.Int64Value(v)
		} else {
			*id = types.Int64Unknown()
		}
	}

	for i := range plan.DNS {
		assignID(&plan.DNS[i].ID, fmt.Sprintf("dns:%d", plan.DNS[i].Port.ValueInt64()))
	}
	for i := range plan.HTTP {
		assignID(&plan.HTTP[i].ID, fmt.Sprintf("http:%d", plan.HTTP[i].Port.ValueInt64()))
	}
	for i := range plan.ICMP {
		assignID(&plan.ICMP[i].ID, "icmp")
	}
	for i := range plan.NAT {
		assignID(&plan.NAT[i].ID, fmt.Sprintf("nat:%s:%d", plan.NAT[i].Proto.ValueString(), plan.NAT[i].Port.ValueInt64()))
	}
	for i := range plan.AnyIngressEgress {
		assignID(&plan.AnyIngressEgress[i].ID, "any-ingress-egress")
	}
	for i := range plan.ProtoIngressEgress {
		assignID(&plan.ProtoIngressEgress[i].ID, fmt.Sprintf("proto-ie:%d", plan.ProtoIngressEgress[i].Proto.ValueInt64()))
	}
	for i := range plan.TCPIngressEgress {
		assignID(&plan.TCPIngressEgress[i].ID, "tcp-ingress-egress")
	}
	for i := range plan.TCPEgress {
		assignID(&plan.TCPEgress[i].ID, "tcp-egress")
	}
	for i := range plan.FragIngressEgress {
		assignID(&plan.FragIngressEgress[i].ID, "frag-ingress-egress")
	}

	// Set each list attribute as a whole (SetAttribute on sub-paths inside
	// ListNestedAttribute doesn't work).
	if plan.DNS != nil {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("dns"), plan.DNS)...)
	}
	if plan.HTTP != nil {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("http"), plan.HTTP)...)
	}
	if plan.ICMP != nil {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("icmp"), plan.ICMP)...)
	}
	if plan.NAT != nil {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("nat"), plan.NAT)...)
	}
	if plan.AnyIngressEgress != nil {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("any_ingress_egress"), plan.AnyIngressEgress)...)
	}
	if plan.ProtoIngressEgress != nil {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("proto_ingress_egress"), plan.ProtoIngressEgress)...)
	}
	if plan.TCPIngressEgress != nil {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("tcp_ingress_egress"), plan.TCPIngressEgress)...)
	}
	if plan.TCPEgress != nil {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("tcp_egress"), plan.TCPEgress)...)
	}
	if plan.FragIngressEgress != nil {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("frag_ingress_egress"), plan.FragIngressEgress)...)
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

	if err := r.readAndPopulate(ctx, state.ServiceID.ValueInt64(), &state); err != nil {
		resp.Diagnostics.AddError("Failed to read services", err.Error())
		return
	}

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
		SSL: m.UpstreamSSL.ValueBool(),
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
