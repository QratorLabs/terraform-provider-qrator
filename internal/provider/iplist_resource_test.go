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

func makeDesired(entries map[string][2]interface{}) map[string]IPListEntryValueModel {
	m := make(map[string]IPListEntryValueModel, len(entries))
	for ip, v := range entries {
		m[ip] = IPListEntryValueModel{
			TTL:     types.Int64Value(v[0].(int64)),
			Comment: types.StringValue(v[1].(string)),
		}
	}
	return m
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

		desired := makeDesired(map[string][2]interface{}{
			"1.2.3.4": {int64(0), ""},
		})
		var d diag.Diagnostics
		r.syncEntries(ctx, 10, nil, desired, false, &d)
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

		desired := makeDesired(map[string][2]interface{}{
			"1.2.3.4": {int64(0), ""},
		})
		var d diag.Diagnostics
		r.syncEntries(ctx, 11, desired, desired, false, &d)
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

		prev := makeDesired(map[string][2]interface{}{
			"9.9.9.9": {int64(0), "old"},
			"1.2.3.4": {int64(0), ""},
		})
		desired := makeDesired(map[string][2]interface{}{
			"1.2.3.4": {int64(0), ""},
			"5.5.5.5": {int64(0), "new"},
		})
		var d diag.Diagnostics
		r.syncEntries(ctx, 12, prev, desired, false, &d)
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

	t.Run("UI-added entry not removed when not in config", func(t *testing.T) {
		apiPath := "/request/domain/15"
		mc := newMockClient().
			OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{
				{"1.2.3.4", int64(0), ""},
				{"9.9.9.9", int64(0), "ui-added"},
			}))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}

		prev := makeDesired(map[string][2]interface{}{
			"1.2.3.4": {int64(0), ""},
		})
		desired := makeDesired(map[string][2]interface{}{
			"1.2.3.4": {int64(0), ""},
		})
		var d diag.Diagnostics
		r.syncEntries(ctx, 15, prev, desired, false, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_remove")); n != 0 {
			t.Errorf("expected 0 remove calls (UI entry must not be removed), got %d", n)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_append")); n != 0 {
			t.Errorf("expected 0 append calls, got %d", n)
		}
	})

	t.Run("changed comment, ttl=0 — remove then append", func(t *testing.T) {
		apiPath := "/request/domain/16"
		mc := newMockClient().
			OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{{"1.2.3.4", int64(0), "old"}})).
			On(apiPath, "whitelist_remove", nil).
			On(apiPath, "whitelist_append", nil)
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}

		desired := makeDesired(map[string][2]interface{}{
			"1.2.3.4": {int64(0), "new"},
		})
		var d diag.Diagnostics
		r.syncEntries(ctx, 16, nil, desired, false, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_remove")); n != 1 {
			t.Errorf("expected 1 remove (ttl=0 can't overwrite in-place), got %d", n)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_append")); n != 1 {
			t.Errorf("expected 1 append, got %d", n)
		}
	})

	t.Run("changed ttl, existing ttl!=0 — append only, no remove", func(t *testing.T) {
		apiPath := "/request/domain/13"
		mc := newMockClient().
			OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{{"1.2.3.4", int64(3600), ""}})).
			On(apiPath, "whitelist_append", nil)
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}

		desired := makeDesired(map[string][2]interface{}{
			"1.2.3.4": {int64(7200), ""},
		})
		var d diag.Diagnostics
		r.syncEntries(ctx, 13, nil, desired, false, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_remove")); n != 0 {
			t.Errorf("expected 0 removes (existing ttl!=0, append overwrites), got %d", n)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_append")); n != 1 {
			t.Errorf("expected 1 append, got %d", n)
		}
	})

	t.Run("exclusive=true removes UI-added entry", func(t *testing.T) {
		apiPath := "/request/domain/17"
		mc := newMockClient().
			OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{
				{"1.2.3.4", int64(0), ""},
				{"9.9.9.9", int64(0), "ui-added"},
			})).
			On(apiPath, "whitelist_remove", nil)
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}

		desired := makeDesired(map[string][2]interface{}{
			"1.2.3.4": {int64(0), ""},
		})
		var d diag.Diagnostics
		r.syncEntries(ctx, 17, nil, desired, true, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_remove")); n != 1 {
			t.Errorf("expected 1 remove (exclusive mode), got %d", n)
		}
		if n := len(mc.CallsFor(apiPath, "whitelist_append")); n != 0 {
			t.Errorf("expected 0 appends, got %d", n)
		}
	})

	t.Run("get error propagates as diagnostic", func(t *testing.T) {
		apiPath := "/request/domain/14"
		mc := newMockClient().OnError(apiPath, "whitelist_get", fmt.Errorf("network error"))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}
		var d diag.Diagnostics
		r.syncEntries(ctx, 14, nil, nil, false, &d)
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

		desired := makeDesired(map[string][2]interface{}{
			"8.8.8.8": {int64(0), ""},
		})
		var d diag.Diagnostics
		r.syncEntries(ctx, 99, nil, desired, false, &d)
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

	t.Run("returns API values for managed IPs", func(t *testing.T) {
		apiPath := "/request/domain/20"
		mc := newMockClient().OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{
			{"10.0.0.2", int64(0), "b"},
			{"10.0.0.1", int64(0), "a"},
		}))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}
		desired := makeDesired(map[string][2]interface{}{
			"10.0.0.1": {int64(0), ""},
			"10.0.0.2": {int64(0), ""},
		})
		got, err := r.readAndReconcile(ctx, 20, desired, false)
		if err != nil {
			t.Fatal(err)
		}
		wantComments := map[string]string{"10.0.0.1": "a", "10.0.0.2": "b"}
		if len(got) != len(wantComments) {
			t.Fatalf("expected %d entries, got %d", len(wantComments), len(got))
		}
		for ip, wantComment := range wantComments {
			e, ok := got[ip]
			if !ok {
				t.Errorf("missing IP %s", ip)
				continue
			}
			if e.Comment.ValueString() != wantComment {
				t.Errorf("IP %s: expected comment %q, got %q", ip, wantComment, e.Comment.ValueString())
			}
		}
	})

	t.Run("entry removed from API is dropped", func(t *testing.T) {
		apiPath := "/request/domain/21"
		mc := newMockClient().OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{
			{"1.1.1.1", int64(0), ""},
		}))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}
		desired := makeDesired(map[string][2]interface{}{
			"1.1.1.1": {int64(0), ""},
			"2.2.2.2": {int64(0), ""},
		})
		got, err := r.readAndReconcile(ctx, 21, desired, false)
		if err != nil || len(got) != 1 {
			t.Fatalf("got len=%d, err=%v", len(got), err)
		}
		if _, ok := got["1.1.1.1"]; !ok {
			t.Errorf("expected 1.1.1.1 in result, got %v", got)
		}
	})

	t.Run("UI-added API entry not included in result", func(t *testing.T) {
		apiPath := "/request/domain/22"
		mc := newMockClient().OnRaw(apiPath, "whitelist_get", ipListTuplesJSON([][]interface{}{
			{"1.1.1.1", int64(0), ""},
			{"2.2.2.2", int64(0), "ui-added"},
			{"3.3.3.3", int64(0), ""},
		}))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}
		desired := makeDesired(map[string][2]interface{}{
			"1.1.1.1": {int64(0), ""},
			"3.3.3.3": {int64(0), ""},
		})
		got, err := r.readAndReconcile(ctx, 22, desired, false)
		if err != nil || len(got) != 2 {
			t.Fatalf("got len=%d, err=%v (expected 2, UI entry must be excluded)", len(got), err)
		}
		for _, ip := range []string{"1.1.1.1", "3.3.3.3"} {
			if _, ok := got[ip]; !ok {
				t.Errorf("expected IP %s in result", ip)
			}
		}
		if _, ok := got["2.2.2.2"]; ok {
			t.Error("UI-added 2.2.2.2 must not appear in result")
		}
	})

	t.Run("get error returned as error", func(t *testing.T) {
		apiPath := "/request/domain/23"
		mc := newMockClient().OnError(apiPath, "whitelist_get", fmt.Errorf("timeout"))
		r := &IPListResource{client: mc, entity: entityDomain, kind: ipListWhitelist}
		_, err := r.readAndReconcile(ctx, 23, nil, false)
		if err == nil {
			t.Error("expected error")
		}
	})
}
