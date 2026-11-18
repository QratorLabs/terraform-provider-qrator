package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// decodeKnownElems decodes the elements of a list of nested objects into T,
// one element at a time, for use during validation when parts of the
// configuration may still be unknown (e.g. fed from a module variable).
//
// The result has one entry per list element, in order, so indexes can be used
// in attribute paths. An entry is nil when the element itself is null or
// unknown. Unknown values nested inside a known element that T cannot
// represent (slices, pointers, structs) are decoded as their zero value
// (UnhandledUnknownAsEmpty), so callers must only rely on fields typed as
// framework values (types.Int64, types.String, ...) and check IsUnknown there.
//
// The list itself must be known and non-null.
func decodeKnownElems[T any](ctx context.Context, l types.List, diags *diag.Diagnostics) []*T {
	return decodeElems[T](ctx, l, diags, false)
}

// decodeFullyKnownElems is like decodeKnownElems, but an entry is also nil
// when the element contains an unknown value anywhere inside. Use it when T
// (or the code reading it) cannot cope with unknown nested values; such
// elements should be validated later, once Terraform knows them.
func decodeFullyKnownElems[T any](ctx context.Context, l types.List, diags *diag.Diagnostics) []*T {
	return decodeElems[T](ctx, l, diags, true)
}

func decodeElems[T any](ctx context.Context, l types.List, diags *diag.Diagnostics, fullyKnownOnly bool) []*T {
	var elems []types.Object
	diags.Append(l.ElementsAs(ctx, &elems, false)...)
	if diags.HasError() {
		return nil
	}
	out := make([]*T, len(elems))
	for i, o := range elems {
		if o.IsNull() || o.IsUnknown() {
			continue
		}
		if fullyKnownOnly {
			tv, err := o.ToTerraformValue(ctx)
			if err != nil {
				diags.AddError("Invalid list element", fmt.Sprintf("element %d: %s", i, err))
				return nil
			}
			if !tv.IsFullyKnown() {
				continue
			}
		}
		var v T
		d := o.As(ctx, &v, basetypes.ObjectAsOptions{UnhandledUnknownAsEmpty: true})
		diags.Append(d...)
		if d.HasError() {
			return nil
		}
		out[i] = &v
	}
	return out
}

// objAttrInt64 returns the known int64 value of an object attribute.
// ok is false when the attribute is missing, null or unknown.
func objAttrInt64(attrs map[string]attr.Value, name string) (int64, bool) {
	v, ok := attrs[name].(basetypes.Int64Value)
	if !ok || v.IsNull() || v.IsUnknown() {
		return 0, false
	}
	return v.ValueInt64(), true
}

// objAttrString returns the known string value of an object attribute.
// ok is false when the attribute is missing, null or unknown.
func objAttrString(attrs map[string]attr.Value, name string) (string, bool) {
	v, ok := attrs[name].(basetypes.StringValue)
	if !ok || v.IsNull() || v.IsUnknown() {
		return "", false
	}
	return v.ValueString(), true
}

// planIDKeyFunc computes the composite key of a planned list entry from its
// attributes. ok is false when a key component is not known yet.
type planIDKeyFunc func(attrs map[string]attr.Value) (key string, ok bool)

// assignPlanIDs sets the "id" attribute of every known entry of the planned
// list attrName from idByKey (matched by key) and writes the list back to the
// plan. Entries without a known key or without a prior ID get an unknown id
// ("known after apply"). Everything else in the entries, including nested
// values that are still unknown, is left untouched, which is why this works on
// framework values instead of decoding into Go structs.
//
// Null or unknown lists are skipped; unknown entries are kept as they are.
func assignPlanIDs(
	ctx context.Context,
	resp *resource.ModifyPlanResponse,
	attrName string,
	planList types.List,
	idByKey map[string]int64,
	keyFn planIDKeyFunc,
) {
	if planList.IsNull() || planList.IsUnknown() {
		return
	}

	elems := planList.Elements()
	newElems := make([]attr.Value, len(elems))
	for i, e := range elems {
		newElems[i] = e
		o, ok := e.(basetypes.ObjectValue)
		if !ok || o.IsNull() || o.IsUnknown() {
			continue
		}
		attrs := o.Attributes()
		newAttrs := make(map[string]attr.Value, len(attrs))
		for k, v := range attrs {
			newAttrs[k] = v
		}
		newAttrs["id"] = types.Int64Unknown()
		if key, ok := keyFn(attrs); ok {
			if id, found := idByKey[key]; found {
				newAttrs["id"] = types.Int64Value(id)
			}
		}
		no, d := types.ObjectValue(o.AttributeTypes(ctx), newAttrs)
		resp.Diagnostics.Append(d...)
		if d.HasError() {
			return
		}
		newElems[i] = no
	}

	nl, d := types.ListValue(planList.ElementType(ctx), newElems)
	resp.Diagnostics.Append(d...)
	if d.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root(attrName), nl)...)
}
