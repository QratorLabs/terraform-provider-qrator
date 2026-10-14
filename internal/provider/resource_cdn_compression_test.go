package provider

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func compressionObj(t *testing.T, gzip, br, deflate, zstd []string) types.Object {
	t.Helper()
	obj, d := types.ObjectValueFrom(context.Background(), contentCompressionAttrTypes, CDNContentCompressionModel{
		Gzip: setOf(gzip...), Br: setOf(br...), Deflate: setOf(deflate...), Zstd: setOf(zstd...),
	})
	if d.HasError() {
		t.Fatal(d)
	}
	return obj
}

func TestCDNSchemaContentCompression(t *testing.T) {
	ctx := context.Background()
	var resp resource.SchemaResponse
	(&CDNResource{}).Schema(ctx, resource.SchemaRequest{}, &resp)
	if _, ok := resp.Schema.Attributes["client_no_cache"]; ok {
		t.Error("client_no_cache must be removed")
	}
	if _, ok := resp.Schema.Attributes["content_compression"]; !ok {
		t.Error("content_compression is missing")
	}
	if _, ok := resp.Schema.Attributes["compress_disabled"]; ok {
		t.Error("compress_disabled must be removed")
	}
}

func TestUpgradeCompressDisabled(t *testing.T) {
	ctx := context.Background()
	all := []string{"*"}
	tests := []struct {
		name     string
		disabled types.List
		want     types.Object
	}{
		{"null", types.ListNull(types.StringType), types.ObjectNull(contentCompressionAttrTypes)},
		{"empty: unmanaged", emptyList(), types.ObjectNull(contentCompressionAttrTypes)},
		{"br", listOf("br"), compressionObj(t, all, nil, all, all)},
		{"gzip and deflate", listOf("gzip", "deflate"), compressionObj(t, nil, all, nil, all)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d diag.Diagnostics
			v2 := upgradeCDNStateV1ToV2(ctx, cdnModelV1{CompressDisabled: tt.disabled}, &d)
			if d.HasError() {
				t.Fatal(d)
			}
			if !v2.ContentCompression.Equal(tt.want) {
				t.Errorf("content_compression = %s, want %s", v2.ContentCompression, tt.want)
			}
		})
	}
}

func TestMimeTypeRE(t *testing.T) {
	valid := []string{"*", "text/html", "application/json", "image/svg+xml", "application/vnd.api+json", "text/*"}
	invalid := []string{"", "text", "text/html; charset=utf-8", " text/html", "text/ html", "a/b/c"}
	for _, v := range valid {
		if !mimeTypeRE.MatchString(v) {
			t.Errorf("%q must be valid", v)
		}
	}
	for _, v := range invalid {
		if mimeTypeRE.MatchString(v) {
			t.Errorf("%q must be invalid", v)
		}
	}
}

func TestContentCompressionRoundTrip(t *testing.T) {
	ctx := context.Background()
	plan := compressionObj(t, []string{"text/html", "application/json"}, []string{"*"}, []string{}, []string{})

	var d diag.Diagnostics
	api, ok := contentCompressionToAPI(ctx, plan, &d)
	if !ok {
		t.Fatal(d)
	}
	b, _ := json.Marshal(api)
	// Every key is present and empty lists are [] (never null).
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(b, &raw)
	for _, k := range []string{"gzip", "br", "deflate", "zstd"} {
		if v, ok := raw[k]; !ok || string(v) == "null" {
			t.Errorf("key %s = %s, want a list", k, v)
		}
	}
	if string(raw["deflate"]) != "[]" {
		t.Errorf("deflate = %s, want []", raw["deflate"])
	}

	var back apiContentCompression
	_ = json.Unmarshal(b, &back)
	got := contentCompressionFromAPI(ctx, back, &d)
	if d.HasError() {
		t.Fatal(d)
	}
	if !got.Equal(plan) {
		t.Errorf("round trip mismatch\n got: %s\nwant: %s", got, plan)
	}
}

func TestContentCompressionFromAPIMissingKey(t *testing.T) {
	var d diag.Diagnostics
	got := contentCompressionFromAPI(context.Background(), apiContentCompression{Gzip: []string{"*"}}, &d)
	if d.HasError() {
		t.Fatal(d)
	}
	if !got.Equal(compressionObj(t, []string{"*"}, nil, nil, nil)) {
		t.Errorf("got %s", got)
	}
}

func TestApplyPlanContentCompression(t *testing.T) {
	ctx := context.Background()
	defaults := compressionObj(t, []string{"*"}, []string{"*"}, []string{"*"}, []string{"*"})
	noBr := compressionObj(t, []string{"*"}, []string{}, []string{"*"}, []string{"*"})

	t.Run("changed value is sent", func(t *testing.T) {
		mc := newMockClient().On(cdnTestPath, "content_compression_set", map[string]interface{}{})
		r := &CDNResource{client: mc}
		plan, state := nullCDNModel(), nullCDNModel()
		plan.ContentCompression, state.ContentCompression = noBr, defaults

		var d diag.Diagnostics
		if !r.applyPlanToAPI(ctx, cdnTestPath, plan, state, &d) {
			t.Fatal(d)
		}
		calls := mc.CallsFor(cdnTestPath, "content_compression_set")
		if len(calls) != 1 {
			t.Fatalf("content_compression_set calls = %d, want 1", len(calls))
		}
		b, _ := json.Marshal(calls[0].Params)
		if want := `{"gzip":["*"],"br":[],"deflate":["*"],"zstd":["*"]}`; string(b) != want {
			t.Errorf("params = %s, want %s", b, want)
		}
	})

	for name, tc := range map[string]struct{ plan, state types.Object }{
		"unchanged":           {noBr, noBr},
		"not configured":      {types.ObjectNull(contentCompressionAttrTypes), defaults},
		"unknown in the plan": {types.ObjectUnknown(contentCompressionAttrTypes), defaults},
	} {
		t.Run(name+": nothing is sent", func(t *testing.T) {
			mc := newMockClient()
			r := &CDNResource{client: mc}
			plan, state := nullCDNModel(), nullCDNModel()
			plan.ContentCompression, state.ContentCompression = tc.plan, tc.state

			var d diag.Diagnostics
			if !r.applyPlanToAPI(ctx, cdnTestPath, plan, state, &d) {
				t.Fatal(d)
			}
			if n := len(mc.Called()); n != 0 {
				t.Errorf("unexpected API calls: %v", mc.Called())
			}
		})
	}
}

func TestReadCDNModelContentCompression(t *testing.T) {
	ctx := context.Background()

	t.Run("managed: read from the API", func(t *testing.T) {
		mc := mockCDNReads(`{}`).
			On(cdnTestPath, "content_compression_get", apiContentCompression{Gzip: []string{"text/html"}, Br: []string{}, Deflate: []string{}, Zstd: []string{"*"}})
		r := &CDNResource{client: mc}
		var d diag.Diagnostics
		got, ok := r.readCDNModel(ctx, 42, CDNModel{
			AccessFilter:       types.ObjectNull(accessFilterAttrTypes),
			ContentCompression: compressionObj(t, []string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}),
			DefaultHost:        types.StringValue("example.com"),
		}, &d)
		if !ok {
			t.Fatal(d)
		}
		want := compressionObj(t, []string{"text/html"}, nil, nil, []string{"*"})
		if !got.ContentCompression.Equal(want) {
			t.Errorf("content_compression = %s", got.ContentCompression)
		}
		if len(mc.CallsFor(cdnTestPath, "client_no_cache_get")) != 0 {
			t.Error("client_no_cache_get must not be called")
		}
	})

	t.Run("unmanaged: not read, stays null", func(t *testing.T) {
		mc := mockCDNReads(`{}`)
		r := &CDNResource{client: mc}
		var d diag.Diagnostics
		got, ok := r.readCDNModel(ctx, 42, CDNModel{
			AccessFilter:       types.ObjectNull(accessFilterAttrTypes),
			ContentCompression: types.ObjectNull(contentCompressionAttrTypes),
			DefaultHost:        types.StringValue("example.com"),
		}, &d)
		if !ok {
			t.Fatal(d)
		}
		if !got.ContentCompression.IsNull() {
			t.Errorf("content_compression = %s, want null", got.ContentCompression)
		}
		if len(mc.CallsFor(cdnTestPath, "content_compression_get")) != 0 {
			t.Error("content_compression_get must not be called")
		}
	})
}
