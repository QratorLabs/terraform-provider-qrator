package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func NormalizeStringList(ctx context.Context, list types.List) (types.List, diag.Diagnostics) {
	if list.IsNull() || list.IsUnknown() {
		return types.ListValueMust(types.StringType, []attr.Value{}), nil
	}
	return list, nil
}

func StringListsEqual(a, b types.List) bool {
	if a.IsNull() && b.IsNull() {
		return true
	}
	if a.IsNull() != b.IsNull() {
		return false
	}
	var av, bv []string
	_ = a.ElementsAs(context.Background(), &av, false)
	_ = b.ElementsAs(context.Background(), &bv, false)
	if len(av) != len(bv) {
		return false
	}
	for i := range av {
		if av[i] != bv[i] {
			return false
		}
	}
	return true
}

func StringListsEqualIgnoreOrder(a, b types.List) bool {
	if a.IsNull() && b.IsNull() {
		return true
	}
	if a.IsNull() != b.IsNull() {
		return false
	}
	var av, bv []string
	_ = a.ElementsAs(context.Background(), &av, false)
	_ = b.ElementsAs(context.Background(), &bv, false)
	if len(av) != len(bv) {
		return false
	}
	m := make(map[string]int, len(av))
	for _, v := range av {
		m[v]++
	}
	for _, v := range bv {
		m[v]--
		if m[v] < 0 {
			return false
		}
	}
	return true
}

func IsNullOrUnknown(v attr.Value) bool {
	return v.IsNull() || v.IsUnknown()
}

func ShouldUpdateList(plan, state types.List, ignoreOrder bool) bool {
	if plan.IsNull() && state.IsNull() {
		return false
	}
	if plan.IsNull() != state.IsNull() {
		return true
	}
	if ignoreOrder {
		return !StringListsEqualIgnoreOrder(plan, state)
	}
	return !StringListsEqual(plan, state)
}
