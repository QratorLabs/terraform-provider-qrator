package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Regression tests for validation/planning with values that are unknown during
// validate/plan (e.g. fed from a module variable): they must not fail with
// "Received unknown value, however the target type cannot handle unknown values".

type svcHarness struct {
	ctx context.Context
	r   resource.Resource
	sch resource.SchemaResponse
	ot  tftypes.Object
}

func newSvcHarness(r resource.Resource) *svcHarness {
	h := &svcHarness{ctx: context.Background(), r: r}
	r.Schema(h.ctx, resource.SchemaRequest{}, &h.sch)
	h.ot = h.sch.Schema.Type().TerraformType(h.ctx).(tftypes.Object)
	return h
}

func nullObjValue(t tftypes.Object, over map[string]tftypes.Value) tftypes.Value {
	m := make(map[string]tftypes.Value, len(t.AttributeTypes))
	for k, at := range t.AttributeTypes {
		m[k] = tftypes.NewValue(at, nil)
	}
	for k, v := range over {
		m[k] = v
	}
	return tftypes.NewValue(t, m)
}

func (h *svcHarness) listType(attr string) tftypes.List {
	return h.ot.AttributeTypes[attr].(tftypes.List)
}

func (h *svcHarness) elemType(attr string) tftypes.Object {
	return h.listType(attr).ElementType.(tftypes.Object)
}

// elem builds a list element: null everywhere except the given values.
func (h *svcHarness) elem(attr string, vals map[string]interface{}) tftypes.Value {
	et := h.elemType(attr)
	over := make(map[string]tftypes.Value, len(vals))
	for k, v := range vals {
		over[k] = tftypes.NewValue(et.AttributeTypes[k], v)
	}
	return nullObjValue(et, over)
}

// raw builds the resource object with one populated list attribute.
func (h *svcHarness) raw(attr string, list tftypes.Value) tftypes.Value {
	return nullObjValue(h.ot, map[string]tftypes.Value{attr: list})
}

func (h *svcHarness) validate(t *testing.T, raw tftypes.Value) resource.ValidateConfigResponse {
	var resp resource.ValidateConfigResponse
	h.r.(resource.ResourceWithValidateConfig).ValidateConfig(h.ctx,
		resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: h.sch.Schema, Raw: raw}}, &resp)
	return resp
}

func TestServicesValidateConfigUnknownValues(t *testing.T) {
	cases := []struct {
		name  string
		r     resource.Resource
		attr  string
		known map[string]interface{}
		field string // field set to unknown
	}{
		{"domain http upstreams", NewDomainServicesResource(), "http", map[string]interface{}{"port": 80}, "upstreams"},
		{"domain tcpproxy upstreams", NewDomainServicesResource(), "tcpproxy", map[string]interface{}{"port": 80}, "upstreams"},
		{"domain websocket upstreams", NewDomainServicesResource(), "websocket", map[string]interface{}{"port": 80}, "upstreams"},
		{"domain nat upstream_ip", NewDomainServicesResource(), "nat", map[string]interface{}{"port": 80, "proto": "tcp"}, "upstream_ip"},
		{"service http upstream", NewServiceServicesResource(), "http", map[string]interface{}{"port": 80}, "upstream"},
		{"service dns port", NewServiceServicesResource(), "dns", nil, "port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSvcHarness(tc.r)
			et := h.elemType(tc.attr)
			vals := map[string]interface{}{}
			for k, v := range tc.known {
				vals[k] = v
			}
			vals[tc.field] = tftypes.UnknownValue
			list := tftypes.NewValue(h.listType(tc.attr), []tftypes.Value{
				h.elem(tc.attr, vals),
				tftypes.NewValue(et, tftypes.UnknownValue), // fully unknown sibling element
			})
			if resp := h.validate(t, h.raw(tc.attr, list)); resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
			}
			// the whole list unknown
			unk := tftypes.NewValue(h.listType(tc.attr), tftypes.UnknownValue)
			if resp := h.validate(t, h.raw(tc.attr, unk)); resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics for unknown list: %v", resp.Diagnostics)
			}
		})
	}
}

func TestServicesValidateConfigStillDetectsDuplicates(t *testing.T) {
	h := newSvcHarness(NewDomainServicesResource())
	et := h.elemType("http")
	list := tftypes.NewValue(h.listType("http"), []tftypes.Value{
		h.elem("http", map[string]interface{}{"port": 80, "upstreams": tftypes.UnknownValue}),
		tftypes.NewValue(et, tftypes.UnknownValue),
		h.elem("http", map[string]interface{}{"port": 80}),
	})
	if resp := h.validate(t, h.raw("http", list)); !resp.Diagnostics.HasError() {
		t.Fatal("expected duplicate service diagnostics")
	}
}

func TestServicesModifyPlanKeepsNestedUnknowns(t *testing.T) {
	cases := []struct {
		name    string
		r       resource.Resource
		attr    string
		state   map[string]interface{}
		plan    map[string]interface{} // id left null/unknown by the framework
		unknown string
	}{
		{"domain http", NewDomainServicesResource(), "http",
			map[string]interface{}{"id": 5, "port": 80}, map[string]interface{}{"port": 80}, "upstreams"},
		{"service http", NewServiceServicesResource(), "http",
			map[string]interface{}{"id": 5, "port": 80}, map[string]interface{}{"port": 80}, "upstream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSvcHarness(tc.r)
			lt := h.listType(tc.attr)

			stateRaw := h.raw(tc.attr, tftypes.NewValue(lt, []tftypes.Value{h.elem(tc.attr, tc.state)}))

			planVals := map[string]interface{}{"id": tftypes.UnknownValue, tc.unknown: tftypes.UnknownValue}
			for k, v := range tc.plan {
				planVals[k] = v
			}
			planRaw := h.raw(tc.attr, tftypes.NewValue(lt, []tftypes.Value{
				h.elem(tc.attr, planVals),
				tftypes.NewValue(h.elemType(tc.attr), tftypes.UnknownValue),
			}))

			plan := tfsdk.Plan{Schema: h.sch.Schema, Raw: planRaw}
			req := resource.ModifyPlanRequest{
				Plan:  plan,
				State: tfsdk.State{Schema: h.sch.Schema, Raw: stateRaw},
			}
			resp := resource.ModifyPlanResponse{Plan: plan}
			h.r.(resource.ResourceWithModifyPlan).ModifyPlan(h.ctx, req, &resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
			}

			got, err := resp.Plan.Raw.ApplyTerraform5AttributePathStep(tftypes.AttributeName(tc.attr))
			if err != nil {
				t.Fatal(err)
			}
			var elems []tftypes.Value
			if err := got.(tftypes.Value).As(&elems); err != nil {
				t.Fatal(err)
			}
			if len(elems) != 2 {
				t.Fatalf("expected 2 elements, got %d", len(elems))
			}
			var first map[string]tftypes.Value
			if err := elems[0].As(&first); err != nil {
				t.Fatal(err)
			}
			if id := first["id"]; !id.IsKnown() {
				t.Fatalf("id should be taken from state, got unknown")
			}
			if first[tc.unknown].IsKnown() {
				t.Fatalf("nested %s should stay unknown", tc.unknown)
			}
			if elems[1].IsKnown() {
				t.Fatalf("unknown sibling element should stay unknown")
			}
		})
	}
}
