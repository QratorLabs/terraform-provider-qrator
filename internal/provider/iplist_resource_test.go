package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ipListTuplesJSON serialises a slice of tuples into the JSON format returned
// by whitelist_get / blacklist_get when called with "tuple" param.
func ipListTuplesJSON(tuples [][]interface{}) json.RawMessage {
	b, err := json.Marshal(tuples)
	if err != nil {
		panic(err)
	}
	return json.RawMessage(b)
}

// ---------------------------------------------------------------------------
// syncEntries
// ---------------------------------------------------------------------------

func TestIPListSyncEntries(t *testing.T) {
	ctx := context.Background()

	t.Run("empty current — appends all desired", func(t *testing.T) {
		apiPath := "/request/domain/10"
		mc := newMockClient().
			OnRaw(apiPath, "whitelist_get", ipListTuplesJSON(nil)).
			On(apiPath, "whitelist_append", nil)
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}

		desired := []IPListEntryModel{
			{IP: types.StringValue("1.2.3.4"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
		}
		var d diag.Diagnostics
		r.syncEntries(ctx, 10, desired, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_append")); n != 1 {
			t.Errorf("expected 1 append call, got %d", n)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_remove")); n != 0 {
			t.Errorf("expected 0 remove calls, got %d", n)
		}
	})

	t.Run("identical current — no append or remove", func(t *testing.T) {
		apiPath := "/request/domain/11"
		mc := newMockClient().
			OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{{"1.2.3.4", int64(0), ""}}))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}

		desired := []IPListEntryModel{
			{IP: types.StringValue("1.2.3.4"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
		}
		var d diag.Diagnostics
		r.syncEntries(ctx, 11, desired, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_append")); n != 0 {
			t.Errorf("expected no append calls, got %d", n)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_remove")); n != 0 {
			t.Errorf("expected no remove calls, got %d", n)
		}
	})

	t.Run("stale entry removed, new entry appended", func(t *testing.T) {
		apiPath := "/request/domain/12"
		mc := newMockClient().
			OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{
				{"9.9.9.9", int64(0), "old"},
				{"1.2.3.4", int64(0), ""},
			})).
			On(apiPath, "whitelist_remove", nil).
			On(apiPath, "whitelist_append", nil)
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}

		desired := []IPListEntryModel{
			{IP: types.StringValue("1.2.3.4"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
			{IP: types.StringValue("5.5.5.5"), TTL: types.Int64Value(0), Comment: types.StringValue("new")},
		}
		var d diag.Diagnostics
		r.syncEntries(ctx, 12, desired, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_remove")); n != 1 {
			t.Errorf("expected 1 remove call, got %d", n)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_append")); n != 1 {
			t.Errorf("expected 1 append call, got %d", n)
		}
	})

	t.Run("changed ttl — remove old entry, append updated", func(t *testing.T) {
		apiPath := "/request/domain/13"
		mc := newMockClient().
			OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{{"1.2.3.4", int64(3600), ""}})).
			On(apiPath, "whitelist_remove", nil).
			On(apiPath, "whitelist_append", nil)
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}

		desired := []IPListEntryModel{
			{IP: types.StringValue("1.2.3.4"), TTL: types.Int64Value(7200), Comment: types.StringValue("")},
		}
		var d diag.Diagnostics
		r.syncEntries(ctx, 13, desired, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_remove")); n != 1 {
			t.Errorf("expected 1 remove, got %d", n)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_append")); n != 1 {
			t.Errorf("expected 1 append, got %d", n)
		}
	})

	t.Run("get error propagates as diagnostic", func(t *testing.T) {
		apiPath := "/request/domain/14"
		mc := newMockClient().OnError(apiPath, "whitelist_get", fmt.Errorf("network error"))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}
		var d diag.Diagnostics
		r.syncEntries(ctx, 14, nil, &d)
		if !d.HasError() {
			t.Error("expected error diagnostic")
		}
	})

	t.Run("blacklist uses blacklist_get and blacklist_append", func(t *testing.T) {
		apiPath := "/request/service/99"
		mc := newMockClient().
			OnRaw(apiPath, "blacklist_get", ipListTuplesJSON(nil)).
			On(apiPath, "blacklist_append", nil)
		r := &IPListResource{client: mc, entity: entityService, kind: ipListBlacklist}

		desired := []IPListEntryModel{
			{IP: types.StringValue("8.8.8.8"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
		}
		var d diag.Diagnostics
		r.syncEntries(ctx, 99, desired, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if n := len(mc.CallsFor(apiPath, "blacklist_append")); n != 1 {
			t.Errorf("expected 1 blacklist_append, got %d", n)
		}
	})
}

// ---------------------------------------------------------------------------
// readAndReconcile
// ---------------------------------------------------------------------------

func TestIPListReadAndReconcile(t *testing.T) {
	ctx := context.Background()

	t.Run("preserves state order", func(t *testing.T) {
		apiPath := "/request/domain/20"
		// API returns b then a; state order is a, b → result should be a, b
		mc := newMockClient().OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{
			{"b.0.0.1", int64(0), ""},
			{"a.0.0.1", int64(0), ""},
		}))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}
		stateEntries := []IPListEntryModel{
			{IP: types.StringValue("a.0.0.1"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
			{IP: types.StringValue("b.0.0.1"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
		}
		var d diag.Diagnostics
		got, err := r.readAndReconcile(ctx, 20, stateEntries, &d)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].IP.ValueString() != "a.0.0.1" || got[1].IP.ValueString() != "b.0.0.1" {
			t.Errorf("expected [a b], got %v", got)
		}
	})

	t.Run("entry removed from API is dropped from result", func(t *testing.T) {
		apiPath := "/request/domain/21"
		mc := newMockClient().OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{
			{"1.1.1.1", int64(0), ""},
		}))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}
		stateEntries := []IPListEntryModel{
			{IP: types.StringValue("1.1.1.1"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
			{IP: types.StringValue("2.2.2.2"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
		}
		var d diag.Diagnostics
		got, err := r.readAndReconcile(ctx, 21, stateEntries, &d)
		if err != nil || len(got) != 1 {
			t.Fatalf("got len=%d, err=%v", len(got), err)
		}
		if got[0].IP.ValueString() != "1.1.1.1" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("new API entry appended after state entries", func(t *testing.T) {
		apiPath := "/request/domain/22"
		mc := newMockClient().OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{
			{"1.1.1.1", int64(0), ""},
			{"3.3.3.3", int64(0), "new"},
		}))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}
		stateEntries := []IPListEntryModel{
			{IP: types.StringValue("1.1.1.1"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
		}
		var d diag.Diagnostics
		got, err := r.readAndReconcile(ctx, 22, stateEntries, &d)
		if err != nil || len(got) != 2 {
			t.Fatalf("got len=%d, err=%v", len(got), err)
		}
		// State-ordered entry comes first.
		if got[0].IP.ValueString() != "1.1.1.1" {
			t.Errorf("expected 1.1.1.1 first, got %v", got)
		}
	})

	t.Run("get error returned as error", func(t *testing.T) {
		apiPath := "/request/domain/23"
		mc := newMockClient().OnError(apiPath, "whitelist_get", fmt.Errorf("timeout"))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}
		var d diag.Diagnostics
		_, err := r.readAndReconcile(ctx, 23, nil, &d)
		if err == nil {
			t.Error("expected error")
		}
	})
}
