package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Universal guard: during validate/plan any value that comes from variables,
// modules, for_each or other resources may be unknown. For every resource this
// test feeds unknown values into every attribute, at every nesting level
// (the attribute itself, an element of a list, a nested object field, ...),
// and requires ValidateConfig and ModifyPlan to cope without errors.
//
// A failure typically means a model decoded config/plan into Go slices,
// pointers or structs ("Value Conversion Error ... cannot handle unknown
// values"). Use types.List / types.Object (see list_unknown_helpers.go).

// uvPaths lists every attribute path of t that can hold an unknown value.
// A step is an attribute name, or "[]" for "the (first) element of a list/map".
func uvPaths(t tftypes.Type, prefix []string) [][]string {
	var out [][]string
	switch tt := t.(type) {
	case tftypes.Object:
		names := make([]string, 0, len(tt.AttributeTypes))
		for k := range tt.AttributeTypes {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			p := append(append([]string{}, prefix...), k)
			out = append(out, p)
			out = append(out, uvPaths(tt.AttributeTypes[k], p)...)
		}
	case tftypes.List:
		p := append(append([]string{}, prefix...), "[]")
		out = append(out, p)
		out = append(out, uvPaths(tt.ElementType, p)...)
	case tftypes.Map:
		p := append(append([]string{}, prefix...), "[]")
		out = append(out, p)
		out = append(out, uvPaths(tt.ElementType, p)...)
	}
	return out
}

// uvBuild builds a value of type t that is null everywhere except along path,
// where lists/maps get a single element, and the final step is unknown.
func uvBuild(t tftypes.Type, path []string) tftypes.Value {
	if len(path) == 0 {
		return tftypes.NewValue(t, tftypes.UnknownValue)
	}
	switch tt := t.(type) {
	case tftypes.Object:
		attrs := make(map[string]tftypes.Value, len(tt.AttributeTypes))
		for k, at := range tt.AttributeTypes {
			attrs[k] = tftypes.NewValue(at, nil)
		}
		attrs[path[0]] = uvBuild(tt.AttributeTypes[path[0]], path[1:])
		return tftypes.NewValue(tt, attrs)
	case tftypes.List:
		return tftypes.NewValue(tt, []tftypes.Value{uvBuild(tt.ElementType, path[1:])})
	case tftypes.Map:
		return tftypes.NewValue(tt, map[string]tftypes.Value{"k": uvBuild(tt.ElementType, path[1:])})
	}
	panic(fmt.Sprintf("uvBuild: cannot descend into %s with %v", t, path))
}

// uvKnown builds a fully known value of type t: lists and maps get one element,
// primitives are null. It stands in for prior state.
func uvKnown(t tftypes.Type) tftypes.Value {
	switch tt := t.(type) {
	case tftypes.Object:
		attrs := make(map[string]tftypes.Value, len(tt.AttributeTypes))
		for k, at := range tt.AttributeTypes {
			attrs[k] = uvKnown(at)
		}
		return tftypes.NewValue(tt, attrs)
	case tftypes.List:
		return tftypes.NewValue(tt, []tftypes.Value{uvKnown(tt.ElementType)})
	case tftypes.Map:
		return tftypes.NewValue(tt, map[string]tftypes.Value{"k": uvKnown(tt.ElementType)})
	}
	return tftypes.NewValue(t, nil)
}

func uvCall(fn func()) (panicked any) {
	defer func() { panicked = recover() }()
	fn()
	return nil
}

func TestAllResourcesTolerateUnknownValues(t *testing.T) {
	ctx := context.Background()
	prov := New("test")()

	for _, newRes := range prov.Resources(ctx) {
		r := newRes()

		var meta resource.MetadataResponse
		r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "qrator"}, &meta)

		var schemaResp resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
		sch := schemaResp.Schema
		ot, ok := sch.Type().TerraformType(ctx).(tftypes.Object)
		if !ok {
			t.Fatalf("%s: schema is not an object", meta.TypeName)
		}

		validator, hasValidate := r.(resource.ResourceWithValidateConfig)
		modifier, hasModify := r.(resource.ResourceWithModifyPlan)
		if !hasValidate && !hasModify {
			continue
		}

		state := tfsdk.State{Schema: sch, Raw: uvKnown(ot)}

		for _, p := range uvPaths(ot, nil) {
			name := meta.TypeName + "/" + strings.Join(p, ".")
			raw := uvBuild(ot, p)

			if hasValidate {
				t.Run("ValidateConfig/"+name, func(t *testing.T) {
					var resp resource.ValidateConfigResponse
					req := resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: sch, Raw: raw}}
					if pn := uvCall(func() { validator.ValidateConfig(ctx, req, &resp) }); pn != nil {
						t.Fatalf("panic: %v", pn)
					}
					if resp.Diagnostics.HasError() {
						t.Fatalf("unexpected diagnostics with unknown value: %v", resp.Diagnostics)
					}
				})
			}

			if hasModify {
				t.Run("ModifyPlan/"+name, func(t *testing.T) {
					plan := tfsdk.Plan{Schema: sch, Raw: raw}
					req := resource.ModifyPlanRequest{
						Config: tfsdk.Config{Schema: sch, Raw: raw},
						Plan:   plan,
						State:  state,
					}
					resp := resource.ModifyPlanResponse{Plan: plan}
					if pn := uvCall(func() { modifier.ModifyPlan(ctx, req, &resp) }); pn != nil {
						t.Fatalf("panic: %v", pn)
					}
					if resp.Diagnostics.HasError() {
						t.Fatalf("unexpected diagnostics with unknown value: %v", resp.Diagnostics)
					}
				})
			}
		}
	}
}
