package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// reorderByPlanOrder
// ---------------------------------------------------------------------------

func TestReorderByPlanOrder(t *testing.T) {
	strKey := func(s *string) string { return *s }

	t.Run("empty api list", func(t *testing.T) {
		got := reorderByPlanOrder([]string{"a", "b"}, []string{}, strKey)
		if len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})

	t.Run("empty plan — api order preserved", func(t *testing.T) {
		got := reorderByPlanOrder([]string{}, []string{"b", "a"}, strKey)
		if len(got) != 2 || got[0] != "b" || got[1] != "a" {
			t.Errorf("expected [b a], got %v", got)
		}
	})

	t.Run("full match — plan order restored", func(t *testing.T) {
		got := reorderByPlanOrder([]string{"c", "a", "b"}, []string{"a", "b", "c"}, strKey)
		want := []string{"c", "a", "b"}
		for i, v := range want {
			if got[i] != v {
				t.Errorf("[%d] = %q, want %q", i, got[i], v)
			}
		}
	})

	t.Run("api has extra items — appended after plan entries", func(t *testing.T) {
		got := reorderByPlanOrder([]string{"b"}, []string{"a", "b", "c"}, strKey)
		if len(got) != 3 || got[0] != "b" {
			t.Errorf("expected b first, got %v", got)
		}
	})

	t.Run("plan entry missing from api is skipped", func(t *testing.T) {
		got := reorderByPlanOrder([]string{"a", "x", "b"}, []string{"b", "a"}, strKey)
		if len(got) != 2 || got[0] != "a" || got[1] != "b" {
			t.Errorf("expected [a b], got %v", got)
		}
	})

	t.Run("struct slice — order by code", func(t *testing.T) {
		plan := []CDNCacheErrorEntryModel{
			{Code: types.Int64Value(502), Timeout: types.Int64Value(60000)},
			{Code: types.Int64Value(503), Timeout: types.Int64Value(60000)},
			{Code: types.Int64Value(500), Timeout: types.Int64Value(60000)},
		}
		api := []CDNCacheErrorEntryModel{
			{Code: types.Int64Value(500), Timeout: types.Int64Value(60000)},
			{Code: types.Int64Value(502), Timeout: types.Int64Value(60000)},
			{Code: types.Int64Value(503), Timeout: types.Int64Value(60000)},
		}
		key := func(m *CDNCacheErrorEntryModel) string {
			return types.Int64Value(m.Code.ValueInt64()).String()
		}
		got := reorderByPlanOrder(plan, api, key)
		wantOrder := []int64{502, 503, 500}
		for i, w := range wantOrder {
			if got[i].Code.ValueInt64() != w {
				t.Errorf("[%d].code = %d, want %d", i, got[i].Code.ValueInt64(), w)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// CDN list converters
// ---------------------------------------------------------------------------

func TestCacheErrorEntriesToModels(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got := cacheErrorEntriesToModels(nil)
		if len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})

	t.Run("converts fields correctly", func(t *testing.T) {
		entries := []cdnCacheErrorEntry{
			{Code: 502, Timeout: 60000},
			{Code: 503, Timeout: 120000},
		}
		got := cacheErrorEntriesToModels(entries)
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		if got[0].Code.ValueInt64() != 502 || got[0].Timeout.ValueInt64() != 60000 {
			t.Errorf("got[0] = {%d, %d}", got[0].Code.ValueInt64(), got[0].Timeout.ValueInt64())
		}
		if got[1].Code.ValueInt64() != 503 || got[1].Timeout.ValueInt64() != 120000 {
			t.Errorf("got[1] = {%d, %d}", got[1].Code.ValueInt64(), got[1].Timeout.ValueInt64())
		}
	})
}

func TestCacheErrorModelsToList(t *testing.T) {
	ctx := context.Background()

	t.Run("empty models", func(t *testing.T) {
		var d diag.Diagnostics
		list := cacheErrorModelsToList(ctx, []CDNCacheErrorEntryModel{}, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if len(list.Elements()) != 0 {
			t.Errorf("len = %d, want 0", len(list.Elements()))
		}
	})

	t.Run("round-trip", func(t *testing.T) {
		entries := []cdnCacheErrorEntry{
			{Code: 502, Timeout: 60000},
			{Code: 504, Timeout: 300000},
		}
		var d diag.Diagnostics
		list := cacheErrorModelsToList(ctx, cacheErrorEntriesToModels(entries), &d)
		if d.HasError() {
			t.Fatal(d)
		}
		var got []CDNCacheErrorEntryModel
		list.ElementsAs(ctx, &got, false)
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		if got[0].Code.ValueInt64() != 502 || got[0].Timeout.ValueInt64() != 60000 {
			t.Errorf("got[0] = {%d, %d}", got[0].Code.ValueInt64(), got[0].Timeout.ValueInt64())
		}
		if got[1].Code.ValueInt64() != 504 || got[1].Timeout.ValueInt64() != 300000 {
			t.Errorf("got[1] = {%d, %d}", got[1].Code.ValueInt64(), got[1].Timeout.ValueInt64())
		}
	})
}

func TestBlockedURIEntriesToModels(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got := blockedURIEntriesToModels(nil)
		if len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})

	t.Run("converts fields correctly", func(t *testing.T) {
		entries := []cdnBlockedURIEntry{
			{URI: "/admin/.*", Code: 403},
			{URI: "/secret/.*", Code: 404},
		}
		got := blockedURIEntriesToModels(entries)
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		if got[0].URI.ValueString() != "/admin/.*" || got[0].Code.ValueInt64() != 403 {
			t.Errorf("got[0] = {%q, %d}", got[0].URI.ValueString(), got[0].Code.ValueInt64())
		}
		if got[1].URI.ValueString() != "/secret/.*" || got[1].Code.ValueInt64() != 404 {
			t.Errorf("got[1] = {%q, %d}", got[1].URI.ValueString(), got[1].Code.ValueInt64())
		}
	})
}

func TestBlockedURIModelsToList(t *testing.T) {
	ctx := context.Background()

	t.Run("empty models", func(t *testing.T) {
		var d diag.Diagnostics
		list := blockedURIModelsToList(ctx, []CDNBlockedURIEntryModel{}, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if len(list.Elements()) != 0 {
			t.Errorf("len = %d, want 0", len(list.Elements()))
		}
	})

	t.Run("round-trip", func(t *testing.T) {
		entries := []cdnBlockedURIEntry{
			{URI: "/admin/.*", Code: 403},
			{URI: "/private/.*", Code: 404},
		}
		var d diag.Diagnostics
		list := blockedURIModelsToList(ctx, blockedURIEntriesToModels(entries), &d)
		if d.HasError() {
			t.Fatal(d)
		}
		var got []CDNBlockedURIEntryModel
		list.ElementsAs(ctx, &got, false)
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		if got[0].URI.ValueString() != "/admin/.*" || got[0].Code.ValueInt64() != 403 {
			t.Errorf("got[0] = {%q, %d}", got[0].URI.ValueString(), got[0].Code.ValueInt64())
		}
		if got[1].URI.ValueString() != "/private/.*" || got[1].Code.ValueInt64() != 404 {
			t.Errorf("got[1] = {%q, %d}", got[1].URI.ValueString(), got[1].Code.ValueInt64())
		}
	})
}
