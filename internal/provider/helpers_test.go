package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestNormalizeStringList(t *testing.T) {
	ctx := context.Background()

	t.Run("null becomes empty list", func(t *testing.T) {
		got, diags := NormalizeStringList(ctx, types.ListNull(types.StringType))
		if diags.HasError() {
			t.Fatalf("unexpected error: %v", diags)
		}
		var elems []string
		got.ElementsAs(ctx, &elems, false)
		if len(elems) != 0 {
			t.Errorf("expected empty list, got %v", elems)
		}
	})

	t.Run("unknown becomes empty list", func(t *testing.T) {
		got, diags := NormalizeStringList(ctx, types.ListUnknown(types.StringType))
		if diags.HasError() {
			t.Fatalf("unexpected error: %v", diags)
		}
		var elems []string
		got.ElementsAs(ctx, &elems, false)
		if len(elems) != 0 {
			t.Errorf("expected empty list, got %v", elems)
		}
	})

	t.Run("non-null returned as-is", func(t *testing.T) {
		input := listOf("a", "b")
		got, diags := NormalizeStringList(ctx, input)
		if diags.HasError() {
			t.Fatalf("unexpected error: %v", diags)
		}
		var elems []string
		got.ElementsAs(ctx, &elems, false)
		if len(elems) != 2 || elems[0] != "a" || elems[1] != "b" {
			t.Errorf("expected [a b], got %v", elems)
		}
	})
}

func TestStringListsEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b types.List
		want bool
	}{
		{"both null", types.ListNull(types.StringType), types.ListNull(types.StringType), true},
		{"one null", types.ListNull(types.StringType), listOf("a"), false},
		{"same elements", listOf("a", "b"), listOf("a", "b"), true},
		{"different elements", listOf("a"), listOf("b"), false},
		{"different length", listOf("a", "b"), listOf("a"), false},
		{"order matters", listOf("a", "b"), listOf("b", "a"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StringListsEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("StringListsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStringListsEqualIgnoreOrder(t *testing.T) {
	tests := []struct {
		name string
		a, b types.List
		want bool
	}{
		{"both null", types.ListNull(types.StringType), types.ListNull(types.StringType), true},
		{"one null", types.ListNull(types.StringType), listOf("a"), false},
		{"same order", listOf("a", "b"), listOf("a", "b"), true},
		{"reversed", listOf("a", "b"), listOf("b", "a"), true},
		{"different", listOf("a", "b"), listOf("a", "c"), false},
		{"different length", listOf("a", "b"), listOf("a"), false},
		{"duplicates match", listOf("a", "a"), listOf("a", "a"), true},
		{"duplicates mismatch", listOf("a", "a"), listOf("a", "b"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StringListsEqualIgnoreOrder(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("StringListsEqualIgnoreOrder() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNullOrUnknown(t *testing.T) {
	tests := []struct {
		name string
		val  types.String
		want bool
	}{
		{"null", types.StringNull(), true},
		{"unknown", types.StringUnknown(), true},
		{"value", types.StringValue("x"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsNullOrUnknown(tt.val)
			if got != tt.want {
				t.Errorf("IsNullOrUnknown() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldUpdateList(t *testing.T) {
	null := types.ListNull(types.StringType)

	tests := []struct {
		name        string
		plan, state types.List
		ignoreOrder bool
		want        bool
	}{
		{"both null", null, null, false, false},
		{"plan null state not", null, listOf("a"), false, true},
		{"state null plan not", listOf("a"), null, false, true},
		{"equal ordered", listOf("a", "b"), listOf("a", "b"), false, false},
		{"different ordered", listOf("a"), listOf("b"), false, true},
		{"same unordered", listOf("b", "a"), listOf("a", "b"), true, false},
		{"different unordered", listOf("a", "c"), listOf("a", "b"), true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldUpdateList(tt.plan, tt.state, tt.ignoreOrder)
			if got != tt.want {
				t.Errorf("ShouldUpdateList() = %v, want %v", got, tt.want)
			}
		})
	}
}
