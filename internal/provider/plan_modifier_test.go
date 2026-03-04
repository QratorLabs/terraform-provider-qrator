package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestComputedUnknownInt64_NullNull_BecomesUnknown(t *testing.T) {
	m := computedUnknownInt64{}
	resp := &planmodifier.Int64Response{
		PlanValue: types.Int64Null(),
	}
	req := planmodifier.Int64Request{
		ConfigValue: types.Int64Null(),
	}

	m.PlanModifyInt64(context.Background(), req, resp)

	if !resp.PlanValue.IsUnknown() {
		t.Errorf("expected Unknown, got %v", resp.PlanValue)
	}
}

func TestComputedUnknownInt64_NullKnown_Unchanged(t *testing.T) {
	m := computedUnknownInt64{}
	resp := &planmodifier.Int64Response{
		PlanValue: types.Int64Value(42),
	}
	req := planmodifier.Int64Request{
		ConfigValue: types.Int64Null(),
	}

	m.PlanModifyInt64(context.Background(), req, resp)

	if resp.PlanValue.IsUnknown() || resp.PlanValue.ValueInt64() != 42 {
		t.Errorf("expected 42, got %v", resp.PlanValue)
	}
}

func TestComputedUnknownInt64_Known_Unchanged(t *testing.T) {
	m := computedUnknownInt64{}
	resp := &planmodifier.Int64Response{
		PlanValue: types.Int64Value(99),
	}
	req := planmodifier.Int64Request{
		ConfigValue: types.Int64Value(99),
	}

	m.PlanModifyInt64(context.Background(), req, resp)

	if resp.PlanValue.ValueInt64() != 99 {
		t.Errorf("expected 99, got %v", resp.PlanValue)
	}
}
