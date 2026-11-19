package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// redirectsValidateHarness builds ValidateConfig requests with arbitrary
// (possibly unknown) values for the redirects attribute.
type redirectsValidateHarness struct {
	t          *testing.T
	ctx        context.Context
	r          *DomainRedirectsResource
	schemaResp resource.SchemaResponse
	objType    tftypes.Object
	listType   tftypes.List
	elemType   tftypes.Object
	fromType   tftypes.Object
	hostType   tftypes.Object
	uriType    tftypes.Object
}

func newRedirectsValidateHarness(t *testing.T) *redirectsValidateHarness {
	h := &redirectsValidateHarness{t: t, ctx: context.Background(), r: &DomainRedirectsResource{}}
	h.r.Schema(h.ctx, resource.SchemaRequest{}, &h.schemaResp)
	h.objType = h.schemaResp.Schema.Type().TerraformType(h.ctx).(tftypes.Object)
	h.listType = h.objType.AttributeTypes["redirects"].(tftypes.List)
	h.elemType = h.listType.ElementType.(tftypes.Object)
	h.fromType = h.elemType.AttributeTypes["from"].(tftypes.Object)
	h.hostType = h.fromType.AttributeTypes["hostname"].(tftypes.Object)
	h.uriType = h.fromType.AttributeTypes["uri"].(tftypes.Object)
	return h
}

// rule builds a redirect rule. port/hostType may be unknown via tftypes.UnknownValue;
// uri == nil means null (match any URI).
func (h *redirectsValidateHarness) rule(port, hostTypeVal interface{}, uriValue *string) tftypes.Value {
	return h.ruleWithHostname(port, hostTypeVal, nil, uriValue)
}

func (h *redirectsValidateHarness) ruleWithHostname(port, hostTypeVal, hostValue interface{}, uriValue *string) tftypes.Value {
	uri := tftypes.NewValue(h.uriType, nil)
	if uriValue != nil {
		uri = tftypes.NewValue(h.uriType, map[string]tftypes.Value{
			"type":  tftypes.NewValue(tftypes.String, "exact"),
			"value": tftypes.NewValue(tftypes.String, *uriValue),
		})
	}
	return tftypes.NewValue(h.elemType, map[string]tftypes.Value{
		"from": tftypes.NewValue(h.fromType, map[string]tftypes.Value{
			"port": tftypes.NewValue(tftypes.Number, port),
			"hostname": tftypes.NewValue(h.hostType, map[string]tftypes.Value{
				"type":  tftypes.NewValue(tftypes.String, hostTypeVal),
				"value": tftypes.NewValue(tftypes.String, hostValue),
			}),
			"uri": uri,
		}),
		"redirect": tftypes.NewValue(h.elemType.AttributeTypes["redirect"], nil),
	})
}

func (h *redirectsValidateHarness) validate(list tftypes.Value) resource.ValidateConfigResponse {
	raw := tftypes.NewValue(h.objType, map[string]tftypes.Value{
		"domain_id": tftypes.NewValue(tftypes.Number, 1),
		"redirects": list,
	})
	req := resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: h.schemaResp.Schema, Raw: raw}}
	var resp resource.ValidateConfigResponse
	h.r.ValidateConfig(h.ctx, req, &resp)
	return resp
}

func (h *redirectsValidateHarness) list(elems ...tftypes.Value) tftypes.Value {
	return tftypes.NewValue(h.listType, elems)
}

func TestDomainRedirectsValidateConfigUnknownAndEmpty(t *testing.T) {
	h := newRedirectsValidateHarness(t)
	for name, v := range map[string]tftypes.Value{
		"unknown list": tftypes.NewValue(h.listType, tftypes.UnknownValue),
		"null list":    tftypes.NewValue(h.listType, nil),
		"empty list":   h.list(),
	} {
		t.Run(name, func(t *testing.T) {
			if resp := h.validate(v); resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
			}
		})
	}
}

func TestDomainRedirectsValidateConfigUnknownElements(t *testing.T) {
	h := newRedirectsValidateHarness(t)
	uri := "/a"

	t.Run("unknown element", func(t *testing.T) {
		resp := h.validate(h.list(tftypes.NewValue(h.elemType, tftypes.UnknownValue)))
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
		}
	})

	t.Run("unknown nested port", func(t *testing.T) {
		resp := h.validate(h.list(h.rule(tftypes.UnknownValue, "any", &uri)))
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
		}
	})

	// Known rules must still be validated when a sibling element is unknown.
	t.Run("known duplicates still reported next to unknown element", func(t *testing.T) {
		resp := h.validate(h.list(
			h.rule(80, "any", nil),
			tftypes.NewValue(h.elemType, tftypes.UnknownValue),
			h.rule(80, "any", nil),
		))
		if !resp.Diagnostics.HasError() {
			t.Fatal("expected duplicate diagnostics, got none")
		}
	})
}

func TestDomainRedirectsValidateConfigDefaultURIHostnames(t *testing.T) {
	h := newRedirectsValidateHarness(t)
	fqdn := func(port int, host string) tftypes.Value {
		return h.ruleWithHostname(port, "fqdn", host, nil)
	}
	for _, tc := range []struct {
		name      string
		rules     []tftypes.Value
		duplicate bool
	}{
		{"existing wildcard domain rules", []tftypes.Value{fqdn(80, "www.example.com"), fqdn(443, "www.example.com"), h.rule(80, "any", nil)}, false},
		{"different hostnames same port", []tftypes.Value{fqdn(80, "www.example.com"), fqdn(80, "api.example.com")}, false},
		{"same hostname different ports", []tftypes.Value{fqdn(80, "www.example.com"), fqdn(443, "www.example.com")}, false},
		{"same hostname same port", []tftypes.Value{fqdn(80, "www.example.com"), fqdn(80, "www.example.com")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.validate(h.list(tc.rules...))
			found := false
			for _, diag := range resp.Diagnostics {
				if strings.Contains(diag.Summary(), "Duplicate default-URI") {
					found = true
				}
			}
			if found != tc.duplicate || (!tc.duplicate && resp.Diagnostics.HasError()) {
				t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
			}
		})
	}
}

func TestDomainRedirectsValidateConfigKnownErrors(t *testing.T) {
	h := newRedirectsValidateHarness(t)

	t.Run("duplicate any-hostname", func(t *testing.T) {
		a, b := "/a", "/b"
		resp := h.validate(h.list(h.rule(80, "any", &a), h.rule(80, "any", &b)))
		// two any-hostname rules on one port is an API error
		if !resp.Diagnostics.HasError() {
			t.Fatal("expected duplicate any-hostname diagnostics")
		}
	})

	t.Run("duplicate default uri", func(t *testing.T) {
		resp := h.validate(h.list(h.rule(80, "any", nil), h.rule(80, "any", nil)))
		if !resp.Diagnostics.HasError() {
			t.Fatal("expected diagnostics")
		}
	})

	t.Run("too many rules", func(t *testing.T) {
		var elems []tftypes.Value
		for i := 0; i < 71; i++ {
			// distinct unknown elements keep this independent from duplicate checks
			elems = append(elems, tftypes.NewValue(h.elemType, tftypes.UnknownValue))
		}
		resp := h.validate(h.list(elems...))
		if !resp.Diagnostics.HasError() {
			t.Fatal("expected too-many-rules diagnostics")
		}
		if !strings.Contains(resp.Diagnostics[0].Summary(), "Too many") {
			t.Fatalf("unexpected diagnostic: %v", resp.Diagnostics)
		}
	})
}
