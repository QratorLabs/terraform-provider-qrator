package provider

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	tftypes "github.com/hashicorp/terraform-plugin-go/tftypes"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func setOf(vals ...string) types.Set {
	elems := make([]attr.Value, len(vals))
	for i, v := range vals {
		elems[i] = types.StringValue(v)
	}
	return types.SetValueMust(types.StringType, elems)
}

func nullSet() types.Set { return types.SetNull(types.StringType) }

func denyList(t *testing.T, entries ...CDNFilterDenyRegexModel) types.List {
	t.Helper()
	l, d := types.ListValueFrom(context.Background(), types.ObjectType{AttrTypes: filterDenyRegexAttrTypes}, entries)
	if d.HasError() {
		t.Fatal(d)
	}
	return l
}

func nullDenyList() types.List {
	return types.ListNull(types.ObjectType{AttrTypes: filterDenyRegexAttrTypes})
}

func denyEntry(regex string, code int64) CDNFilterDenyRegexModel {
	return CDNFilterDenyRegexModel{Regex: types.StringValue(regex), StatusCode: types.Int64Value(code)}
}

// filterObj converts a model to types.Object, failing the test on error.
func filterObj(t *testing.T, m CDNAccessFilterModel) types.Object {
	t.Helper()
	var d diag.Diagnostics
	obj := accessFilterModelToObject(context.Background(), m, &d)
	if d.HasError() {
		t.Fatal(d)
	}
	return obj
}

// emptyFilterModel returns a model with every attribute null.
func emptyFilterModel() CDNAccessFilterModel {
	return CDNAccessFilterModel{SkipIPs: nullSet()}
}

func toAPIJSON(t *testing.T, m CDNAccessFilterModel) string {
	t.Helper()
	api, d := accessFilterToAPI(context.Background(), m)
	if d.HasError() {
		t.Fatal(d)
	}
	b, err := json.Marshal(api)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func fromAPIJSON(t *testing.T, raw string, ref *CDNAccessFilterModel) CDNAccessFilterModel {
	t.Helper()
	var api apiCdnFilter
	if err := json.Unmarshal([]byte(raw), &api); err != nil {
		t.Fatal(err)
	}
	m, d := accessFilterFromAPI(context.Background(), api, ref)
	if d.HasError() {
		t.Fatal(d)
	}
	return m
}

func assertFilterEqual(t *testing.T, got, want CDNAccessFilterModel) {
	t.Helper()
	g, w := filterObj(t, got), filterObj(t, want)
	if !g.Equal(w) {
		t.Errorf("filter mismatch\n got: %s\nwant: %s", g, w)
	}
}

// ---------------------------------------------------------------------------
// schema & validators
// ---------------------------------------------------------------------------

func TestCDNSchemaValid(t *testing.T) {
	ctx := context.Background()
	var resp resource.SchemaResponse
	(&CDNResource{}).Schema(ctx, resource.SchemaRequest{}, &resp)
	if d := resp.Schema.ValidateImplementation(ctx); d.HasError() {
		t.Fatalf("schema is invalid: %v", d)
	}
	if resp.Schema.Version != 2 {
		t.Errorf("schema version = %d, want 2", resp.Schema.Version)
	}
	for _, removed := range []string{"blocked_uri", "white_uri"} {
		if _, ok := resp.Schema.Attributes[removed]; ok {
			t.Errorf("attribute %q must be removed", removed)
		}
	}
	if _, ok := resp.Schema.Attributes["access_filter"]; !ok {
		t.Error("attribute access_filter is missing")
	}
}

func TestCheckIPOrCIDR(t *testing.T) {
	tests := []struct {
		in    string
		valid bool
	}{
		{"8.8.8.8", true},
		{"8.8.8.0/24", true},
		{"8.8.8.1/24", false}, // not masked
		{"10.0.0.0/8", false}, // prefix shorter than /14
		{"10.0.0.0/14", true}, // shortest allowed
		{"2001:db8::/32", true},
		{"2001:DB8::/32", false}, // upper case
		{"2001:0db8::1", false},  // not compressed
		{"2001:db8::1", true},
		{"fe80::1%eth0", false},
		{"8.8.8.8/32", true},
		{"not-an-ip", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			msg := checkIPOrCIDR(tt.in)
			if (msg == "") != tt.valid {
				t.Errorf("checkIPOrCIDR(%q) = %q, want valid=%v", tt.in, msg, tt.valid)
			}
		})
	}
}

func runInt64Validators(vs []validator.Int64, v int64) bool {
	for _, val := range vs {
		var resp validator.Int64Response
		val.ValidateInt64(context.Background(), validator.Int64Request{
			Path:        path.Root("x"),
			ConfigValue: types.Int64Value(v),
		}, &resp)
		if resp.Diagnostics.HasError() {
			return false
		}
	}
	return true
}

func TestFilterStatusCodeValidators(t *testing.T) {
	valid := []int64{200, 403, 404, 405, 429, 451, 503, 599}
	invalid := []int64{199, 204, 300, 301, 304, 308, 407, 426, 511, 600}
	for _, c := range valid {
		if !runInt64Validators(filterStatusCodeValidators(), c) {
			t.Errorf("code %d must be valid", c)
		}
	}
	for _, c := range invalid {
		if runInt64Validators(filterStatusCodeValidators(), c) {
			t.Errorf("code %d must be invalid", c)
		}
	}
}

// ---------------------------------------------------------------------------

func TestAccessFilterToAPI(t *testing.T) {
	t.Run("empty filter sends every section as null", func(t *testing.T) {
		got := toAPIJSON(t, emptyFilterModel())
		want := `{"skip":null,"geo":null,"ip":null,"uri":null,"user_agent":null,"referer":null,"method":null}`
		if got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
	})

	t.Run("all sections", func(t *testing.T) {
		m := CDNAccessFilterModel{
			SkipIPs: setOf("8.8.4.0/24"),
			IP: &CDNFilterListRulesModel{
				Allow: nullSet(), AllowStatusCode: types.Int64Null(),
				Deny: setOf("1.2.3.0/24"), DenyStatusCode: types.Int64Value(403),
			},
			Geo: &CDNFilterListRulesModel{
				Allow: nullSet(), AllowStatusCode: types.Int64Null(),
				Deny: setOf("CN"), DenyStatusCode: types.Int64Value(405),
			},
			Method: &CDNFilterListRulesModel{
				Allow: setOf("GET"), AllowStatusCode: types.Int64Value(404),
				Deny: nullSet(), DenyStatusCode: types.Int64Null(),
			},
			URI: &CDNFilterURIRulesModel{
				Allow: listOf("^/static/"), AllowStatusCode: types.Int64Value(404),
				Deny: denyList(t, denyEntry("^/admin", 404)),
			},
			UserAgent: &CDNFilterHeaderRulesModel{
				Allow: types.ListNull(types.StringType), AllowStatusCode: types.Int64Null(),
				Deny: denyList(t, denyEntry("^BadBot", 405)), BlockEmpty: types.BoolValue(true),
			},
			Referer: &CDNFilterHeaderRulesModel{
				Allow: listOf("^https://example\\.com"), AllowStatusCode: types.Int64Null(),
				Deny: nullDenyList(), BlockEmpty: types.BoolValue(false),
			},
		}
		got := toAPIJSON(t, m)
		want := `{"skip":{"ip":["8.8.4.0/24"]},` +
			`"geo":{"allow":[],"allow_rule_blocking_http_status_code":null,"deny":["CN"],"deny_rule_blocking_http_status_code":405},` +
			`"ip":{"allow":[],"allow_rule_blocking_http_status_code":null,"deny":["1.2.3.0/24"],"deny_rule_blocking_http_status_code":403},` +
			`"uri":{"allow":[{"regex":"^/static/"}],"allow_rule_blocking_http_status_code":404,"deny":[{"regex":"^/admin","http_status_code":404}]},` +
			`"user_agent":{"allow":[],"allow_rule_blocking_http_status_code":null,"deny":[{"regex":"^BadBot","http_status_code":405}],"block_without_user_agent":true},` +
			`"referer":{"allow":[{"regex":"^https://example\\.com"}],"allow_rule_blocking_http_status_code":null,"deny":[],"block_without_referer":false},` +
			`"method":{"allow":["GET"],"allow_rule_blocking_http_status_code":404,"deny":[],"deny_rule_blocking_http_status_code":null}}`
		if got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
	})

	t.Run("sections without rules are sent as null", func(t *testing.T) {
		m := emptyFilterModel()
		m.SkipIPs = setOf()
		m.Geo = &CDNFilterListRulesModel{Allow: setOf(), AllowStatusCode: types.Int64Value(403), Deny: nullSet(), DenyStatusCode: types.Int64Null()}
		m.URI = &CDNFilterURIRulesModel{Allow: listOf(), AllowStatusCode: types.Int64Null(), Deny: nullDenyList()}
		m.UserAgent = &CDNFilterHeaderRulesModel{Allow: listOf(), AllowStatusCode: types.Int64Null(), Deny: nullDenyList(), BlockEmpty: types.BoolValue(false)}
		got := toAPIJSON(t, m)
		want := `{"skip":null,"geo":null,"ip":null,"uri":null,"user_agent":null,"referer":null,"method":null}`
		if got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
	})

	t.Run("block_empty alone keeps the header section", func(t *testing.T) {
		m := emptyFilterModel()
		m.Referer = &CDNFilterHeaderRulesModel{Allow: types.ListNull(types.StringType), AllowStatusCode: types.Int64Null(), Deny: nullDenyList(), BlockEmpty: types.BoolValue(true)}
		got := toAPIJSON(t, m)
		want := `{"skip":null,"geo":null,"ip":null,"uri":null,"user_agent":null,` +
			`"referer":{"allow":[],"allow_rule_blocking_http_status_code":null,"deny":[],"block_without_referer":true},"method":null}`
		if got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
	})
}

// ---------------------------------------------------------------------------
// API -> model
// ---------------------------------------------------------------------------

func TestAccessFilterFromAPI(t *testing.T) {
	t.Run("nothing configured, no ref", func(t *testing.T) {
		got := fromAPIJSON(t, `{"skip":null,"geo":null,"ip":null,"uri":null,"user_agent":null,"referer":null,"method":null}`, nil)
		assertFilterEqual(t, got, emptyFilterModel())
	})

	t.Run("documentation example, no ref", func(t *testing.T) {
		raw := `{"skip":{"ip":["8.8.4.0/24"]},"geo":{"deny":["CN"],"deny_rule_blocking_http_status_code":405},"ip":null,` +
			`"uri":{"deny":[{"regex":"^foo#","http_status_code":404}]},"user_agent":null,"referer":null,` +
			`"method":{"allow":["GET","HEAD"],"allow_rule_blocking_http_status_code":404}}`
		got := fromAPIJSON(t, raw, nil)
		want := CDNAccessFilterModel{
			SkipIPs: setOf("8.8.4.0/24"),
			Geo:     &CDNFilterListRulesModel{Allow: nullSet(), AllowStatusCode: types.Int64Null(), Deny: setOf("CN"), DenyStatusCode: types.Int64Value(405)},
			Method:  &CDNFilterListRulesModel{Allow: setOf("GET", "HEAD"), AllowStatusCode: types.Int64Value(404), Deny: nullSet(), DenyStatusCode: types.Int64Null()},
			URI:     &CDNFilterURIRulesModel{Allow: types.ListNull(types.StringType), AllowStatusCode: types.Int64Null(), Deny: denyList(t, denyEntry("^foo#", 404))},
		}
		assertFilterEqual(t, got, want)
	})

	t.Run("header section with block flag only", func(t *testing.T) {
		raw := `{"user_agent":{"block_without_user_agent":true},"referer":{"block_without_referer":false,"deny":[{"regex":"x","http_status_code":404}]}}`
		got := fromAPIJSON(t, raw, nil)
		want := emptyFilterModel()
		want.UserAgent = &CDNFilterHeaderRulesModel{Allow: types.ListNull(types.StringType), AllowStatusCode: types.Int64Null(), Deny: nullDenyList(), BlockEmpty: types.BoolValue(true)}
		want.Referer = &CDNFilterHeaderRulesModel{Allow: types.ListNull(types.StringType), AllowStatusCode: types.Int64Null(), Deny: denyList(t, denyEntry("x", 404)), BlockEmpty: types.BoolValue(false)}
		assertFilterEqual(t, got, want)
	})

	t.Run("empty representations from ref are kept", func(t *testing.T) {
		ref := CDNAccessFilterModel{
			SkipIPs: setOf(),
			Geo:     &CDNFilterListRulesModel{Allow: nullSet(), AllowStatusCode: types.Int64Null(), Deny: setOf(), DenyStatusCode: types.Int64Value(403)},
			IP:      &CDNFilterListRulesModel{Allow: nullSet(), AllowStatusCode: types.Int64Null(), Deny: nullSet(), DenyStatusCode: types.Int64Null()},
			URI:     &CDNFilterURIRulesModel{Allow: listOf(), AllowStatusCode: types.Int64Null(), Deny: nullDenyList()},
			UserAgent: &CDNFilterHeaderRulesModel{
				Allow: types.ListNull(types.StringType), AllowStatusCode: types.Int64Null(), Deny: nullDenyList(), BlockEmpty: types.BoolValue(false),
			},
		}
		got := fromAPIJSON(t, `{"skip":null,"geo":null,"ip":null,"uri":null,"user_agent":null,"referer":null,"method":null}`, &ref)
		assertFilterEqual(t, got, ref)
	})

	t.Run("empty rule inside a non-empty section keeps ref form", func(t *testing.T) {
		ref := emptyFilterModel()
		ref.Geo = &CDNFilterListRulesModel{Allow: setOf("US"), AllowStatusCode: types.Int64Null(), Deny: setOf(), DenyStatusCode: types.Int64Value(403)}
		got := fromAPIJSON(t, `{"geo":{"allow":["US"],"allow_rule_blocking_http_status_code":null}}`, &ref)
		assertFilterEqual(t, got, ref)
	})

	t.Run("rules removed outside Terraform show up as null", func(t *testing.T) {
		ref := emptyFilterModel()
		ref.Geo = &CDNFilterListRulesModel{Allow: setOf("US"), AllowStatusCode: types.Int64Null(), Deny: nullSet(), DenyStatusCode: types.Int64Null()}
		ref.UserAgent = &CDNFilterHeaderRulesModel{Allow: types.ListNull(types.StringType), AllowStatusCode: types.Int64Null(), Deny: nullDenyList(), BlockEmpty: types.BoolValue(true)}
		got := fromAPIJSON(t, `{}`, &ref)
		assertFilterEqual(t, got, emptyFilterModel())
	})

	t.Run("regex allow follows ref order, deny keeps API order", func(t *testing.T) {
		ref := emptyFilterModel()
		ref.URI = &CDNFilterURIRulesModel{
			Allow:           listOf("b", "a"),
			AllowStatusCode: types.Int64Value(404),
			Deny:            denyList(t, denyEntry("y", 404), denyEntry("x", 404)),
		}
		raw := `{"uri":{"allow":[{"regex":"a"},{"regex":"b"},{"regex":"c"}],"allow_rule_blocking_http_status_code":404,` +
			`"deny":[{"regex":"x","http_status_code":404},{"regex":"y","http_status_code":404}]}}`
		got := fromAPIJSON(t, raw, &ref)
		want := emptyFilterModel()
		want.URI = &CDNFilterURIRulesModel{
			Allow:           listOf("b", "a", "c"),
			AllowStatusCode: types.Int64Value(404),
			// The first matching deny entry wins, so a reordering in the API
			// is a real change and must not be hidden.
			Deny: denyList(t, denyEntry("x", 404), denyEntry("y", 404)),
		}
		assertFilterEqual(t, got, want)
	})
}

// TestAccessFilterRoundTrip checks that what is sent by filter_set and read back
// by filter_get reproduces the plan exactly; otherwise Terraform would report
// "Provider produced inconsistent result after apply".
func TestAccessFilterRoundTrip(t *testing.T) {
	cases := map[string]CDNAccessFilterModel{
		"empty": emptyFilterModel(),
		"empty spelled with [] and {}": {
			SkipIPs: setOf(),
			Geo:     &CDNFilterListRulesModel{Allow: setOf(), AllowStatusCode: types.Int64Null(), Deny: nullSet(), DenyStatusCode: types.Int64Null()},
			URI:     &CDNFilterURIRulesModel{Allow: listOf(), AllowStatusCode: types.Int64Null(), Deny: denyList(t)},
			Referer: &CDNFilterHeaderRulesModel{Allow: types.ListNull(types.StringType), AllowStatusCode: types.Int64Null(), Deny: nullDenyList(), BlockEmpty: types.BoolValue(false)},
		},
		"full": {
			SkipIPs: setOf("8.8.4.0/24", "2001:db8::/32"),
			IP:      &CDNFilterListRulesModel{Allow: setOf("1.2.3.4"), AllowStatusCode: types.Int64Value(403), Deny: setOf("5.6.0.0/16"), DenyStatusCode: types.Int64Null()},
			Geo:     &CDNFilterListRulesModel{Allow: nullSet(), AllowStatusCode: types.Int64Null(), Deny: setOf("CN", "A1"), DenyStatusCode: types.Int64Value(451)},
			Method:  &CDNFilterListRulesModel{Allow: setOf("GET", "HEAD"), AllowStatusCode: types.Int64Value(405), Deny: nullSet(), DenyStatusCode: types.Int64Null()},
			URI:     &CDNFilterURIRulesModel{Allow: listOf("^/static/", "^/img/"), AllowStatusCode: types.Int64Value(404), Deny: denyList(t, denyEntry("^/admin", 404), denyEntry("^/old", 410))},
			UserAgent: &CDNFilterHeaderRulesModel{
				Allow: types.ListNull(types.StringType), AllowStatusCode: types.Int64Null(),
				Deny: denyList(t, denyEntry("^BadBot", 405)), BlockEmpty: types.BoolValue(true),
			},
			Referer: &CDNFilterHeaderRulesModel{
				Allow: listOf("^https://example\\.com"), AllowStatusCode: types.Int64Value(403),
				Deny: nullDenyList(), BlockEmpty: types.BoolValue(false),
			},
		},
	}
	for name, plan := range cases {
		t.Run(name, func(t *testing.T) {
			sent := toAPIJSON(t, plan)
			got := fromAPIJSON(t, sent, &plan)
			assertFilterEqual(t, got, plan)
		})
	}
}

// ---------------------------------------------------------------------------
// state upgrade
// ---------------------------------------------------------------------------

func blockedURIList(t *testing.T, entries ...CDNBlockedURIEntryModel) types.List {
	t.Helper()
	l, d := types.ListValueFrom(context.Background(), types.ObjectType{AttrTypes: map[string]attr.Type{
		"uri":  types.StringType,
		"code": types.Int64Type,
	}}, entries)
	if d.HasError() {
		t.Fatal(d)
	}
	return l
}

func TestUpgradeCDNStateV1ToV2(t *testing.T) {
	ctx := context.Background()

	t.Run("blocked_uri and white_uri move to access_filter.uri", func(t *testing.T) {
		v1 := cdnModelV1{
			BlockedURI: blockedURIList(t,
				CDNBlockedURIEntryModel{URI: types.StringValue("/admin/.*"), Code: types.Int64Value(403)},
				CDNBlockedURIEntryModel{URI: types.StringValue("/old/.*"), Code: types.Int64Value(410)},
			),
			WhiteURI: listOf("/api/.*", "/static/.*"),
		}
		var d diag.Diagnostics
		v2 := upgradeCDNStateV1ToV2(ctx, v1, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		want := emptyFilterModel()
		want.URI = &CDNFilterURIRulesModel{
			Allow:           listOf("/api/.*", "/static/.*"),
			AllowStatusCode: types.Int64Value(404),
			Deny:            denyList(t, denyEntry("/admin/.*", 403), denyEntry("/old/.*", 410)),
		}
		if !v2.AccessFilter.Equal(filterObj(t, want)) {
			t.Errorf("access_filter = %s", v2.AccessFilter)
		}
	})

	t.Run("only blocked_uri: allow stays null without status code", func(t *testing.T) {
		v1 := cdnModelV1{
			BlockedURI: blockedURIList(t, CDNBlockedURIEntryModel{URI: types.StringValue("/x"), Code: types.Int64Value(404)}),
			WhiteURI:   emptyList(),
		}
		var d diag.Diagnostics
		v2 := upgradeCDNStateV1ToV2(ctx, v1, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		want := emptyFilterModel()
		want.URI = &CDNFilterURIRulesModel{
			Allow:           types.ListNull(types.StringType),
			AllowStatusCode: types.Int64Null(),
			Deny:            denyList(t, denyEntry("/x", 404)),
		}
		if !v2.AccessFilter.Equal(filterObj(t, want)) {
			t.Errorf("access_filter = %s", v2.AccessFilter)
		}
	})

	t.Run("nothing to migrate leaves access_filter null", func(t *testing.T) {
		v1 := cdnModelV1{
			DomainID:   types.Int64Value(7),
			BlockedURI: blockedURIList(t),
			WhiteURI:   emptyList(),
			WebP:       types.Int64Value(80),
		}
		var d diag.Diagnostics
		v2 := upgradeCDNStateV1ToV2(ctx, v1, &d)
		if d.HasError() {
			t.Fatal(d)
		}
		if !v2.AccessFilter.IsNull() {
			t.Errorf("access_filter = %s, want null", v2.AccessFilter)
		}
		if v2.DomainID.ValueInt64() != 7 || v2.WebP.ValueInt64() != 80 {
			t.Errorf("other fields not copied: %+v", v2)
		}
	})
}

// TestCDNUpgradeStateEndToEnd runs the registered upgraders against raw prior
// state, the way Terraform invokes them.
func TestCDNUpgradeStateEndToEnd(t *testing.T) {
	ctx := context.Background()
	r := &CDNResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	upgraders := r.UpgradeState(ctx)

	cacheErrType := types.ObjectType{AttrTypes: cacheErrorAttrTypes}
	common := func() map[string]attr.Value {
		return map[string]attr.Value{
			"domain_id":                   types.Int64Value(42),
			"access_control_allow_origin": emptyList(),
			"cache_control":               types.StringValue("cdn"),
			"client_no_cache":             types.BoolValue(false),
			"redirect_code":               types.Int64Null(),
			"client_headers":              emptyList(),
			"client_ip_header":            types.StringValue(""),
			"upstream_headers":            emptyList(),
			"http2":                       types.BoolValue(true),
			"cache_errors":                types.ListValueMust(cacheErrType, []attr.Value{}),
			"compress_disabled":           emptyList(),
			"blocked_uri": blockedURIList(t, CDNBlockedURIEntryModel{
				URI: types.StringValue("/admin/.*"), Code: types.Int64Value(403),
			}),
			"white_uri":    listOf("/static/.*"),
			"webp":         types.Int64Value(0),
			"tls_versions": listOf("TLSv1.2", "TLSv1.3"),
			"default_host": types.StringValue("example.com"),
		}
	}

	run := func(t *testing.T, version int64, values map[string]attr.Value) CDNModel {
		t.Helper()
		up := upgraders[version]
		prior := tfsdkStateFromValues(t, up.PriorSchema, values)
		req := resource.UpgradeStateRequest{State: &prior}
		resp := resource.UpgradeStateResponse{State: emptyTfsdkState(t, schemaResp.Schema)}
		up.StateUpgrader(ctx, req, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatal(resp.Diagnostics)
		}
		var got CDNModel
		if d := resp.State.Get(ctx, &got); d.HasError() {
			t.Fatal(d)
		}
		return got
	}

	wantFilter := emptyFilterModel()
	wantFilter.URI = &CDNFilterURIRulesModel{
		Allow:           listOf("/static/.*"),
		AllowStatusCode: types.Int64Value(404),
		Deny:            denyList(t, denyEntry("/admin/.*", 403)),
	}

	t.Run("v1", func(t *testing.T) {
		values := common()
		values["cache_query_params"] = types.ObjectValueMust(cacheQueryParamsAttrTypes, map[string]attr.Value{
			"mode":   types.StringValue("use"),
			"params": listOf("page"),
		})
		got := run(t, 1, values)
		if !got.AccessFilter.Equal(filterObj(t, wantFilter)) {
			t.Errorf("access_filter = %s", got.AccessFilter)
		}
		if got.DomainID.ValueInt64() != 42 || got.DefaultHost.ValueString() != "example.com" {
			t.Errorf("fields not preserved: %+v", got)
		}
		var cqp CDNCacheQueryParamsModel
		got.CacheQueryParams.As(ctx, &cqp, basetypesObjectAsOptions)
		if cqp.Mode.ValueString() != "use" {
			t.Errorf("cache_query_params.mode = %s", cqp.Mode)
		}
	})

	t.Run("v0", func(t *testing.T) {
		values := common()
		values["cache_ignore_params"] = types.BoolValue(true)
		values["cache_errors_permanent"] = types.ListValueMust(cacheErrType, []attr.Value{})
		got := run(t, 0, values)
		if !got.AccessFilter.Equal(filterObj(t, wantFilter)) {
			t.Errorf("access_filter = %s", got.AccessFilter)
		}
		var cqp CDNCacheQueryParamsModel
		got.CacheQueryParams.As(ctx, &cqp, basetypesObjectAsOptions)
		if cqp.Mode.ValueString() != "use" || len(cqp.Params.Elements()) != 0 {
			t.Errorf("cache_query_params = %s", got.CacheQueryParams)
		}
	})
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

const cdnTestPath = "/request/cdn/42"

// mockCDNReads registers responses for every *_get method used by readCDNModel.
func mockCDNReads(filter string) *mockClient {
	return newMockClient().
		On(cdnTestPath, "access_control_allow_origin_get", []string{}).
		On(cdnTestPath, "cache_control_get", "cdn").
		OnRaw(cdnTestPath, "cache_query_params_get", json.RawMessage(`{"mode":"ignore","params":null}`)).
		OnRaw(cdnTestPath, "redirect_get", json.RawMessage(`null`)).
		On(cdnTestPath, "client_headers_get", []string{}).
		On(cdnTestPath, "client_ip_header_get", "").
		On(cdnTestPath, "upstream_headers_get", []string{}).
		On(cdnTestPath, "http2_get", true).
		On(cdnTestPath, "cache_errors_get", []cdnCacheErrorEntry{}).
		OnRaw(cdnTestPath, "filter_get", json.RawMessage(filter)).
		On(cdnTestPath, "webp_get", 0).
		On(cdnTestPath, "tls_versions_get", []string{"TLSv1.2"}).
		On(cdnTestPath, "default_host", "example.com")
}

func TestReadCDNModelAccessFilter(t *testing.T) {
	ctx := context.Background()
	mc := mockCDNReads(`{"skip":null,"geo":{"deny":["CN"],"deny_rule_blocking_http_status_code":null},"ip":null,"uri":null,"user_agent":null,"referer":null,"method":null}`)
	r := &CDNResource{client: mc}

	var d diag.Diagnostics
	got, ok := r.readCDNModel(ctx, 42, CDNModel{
		AccessFilter: types.ObjectUnknown(accessFilterAttrTypes),
		DefaultHost:  types.StringUnknown(),
	}, &d)
	if !ok || d.HasError() {
		t.Fatal(d)
	}
	want := emptyFilterModel()
	want.Geo = &CDNFilterListRulesModel{Allow: nullSet(), AllowStatusCode: types.Int64Null(), Deny: setOf("CN"), DenyStatusCode: types.Int64Null()}
	if !got.AccessFilter.Equal(filterObj(t, want)) {
		t.Errorf("access_filter = %s", got.AccessFilter)
	}
	// cache_query_params.params is Required: null from the API must become [].
	var cqp CDNCacheQueryParamsModel
	got.CacheQueryParams.As(ctx, &cqp, basetypesObjectAsOptions)
	if cqp.Params.IsNull() {
		t.Error("cache_query_params.params must not be null")
	}
	for _, removed := range []string{"blocked_uri_get", "white_uri_get"} {
		if calls := mc.CallsFor(cdnTestPath, removed); len(calls) != 0 {
			t.Errorf("%s must not be called", removed)
		}
	}
}

func TestReadCDNModelUnmanagedFilter(t *testing.T) {
	ctx := context.Background()
	mc := mockCDNReads(`{"geo":{"deny":["CN"]}}`)
	r := &CDNResource{client: mc}

	var d diag.Diagnostics
	got, ok := r.readCDNModel(ctx, 42, CDNModel{
		AccessFilter: types.ObjectNull(accessFilterAttrTypes),
		DefaultHost:  types.StringValue("example.com"),
	}, &d)
	if !ok || d.HasError() {
		t.Fatal(d)
	}
	if !got.AccessFilter.IsNull() {
		t.Errorf("unmanaged access_filter must stay null, got %s", got.AccessFilter)
	}
	if calls := mc.CallsFor(cdnTestPath, "filter_get"); len(calls) != 0 {
		t.Error("filter_get must not be called for an unmanaged filter")
	}
}

// nullCDNModel returns a CDNModel whose attributes are all null, so that
// applyPlanToAPI only acts on the fields a test sets.
func nullCDNModel() CDNModel {
	return CDNModel{
		AccessControlAllowOrigin: types.ListNull(types.StringType),
		CacheControl:             types.StringNull(),
		RedirectCode:             types.Int64Null(),
		CacheQueryParams:         types.ObjectNull(cacheQueryParamsAttrTypes),
		ClientHeaders:            types.ListNull(types.StringType),
		ClientIPHeader:           types.StringNull(),
		UpstreamHeaders:          types.ListNull(types.StringType),
		HTTP2:                    types.BoolNull(),
		CacheErrors:              types.ListNull(types.ObjectType{AttrTypes: cacheErrorAttrTypes}),
		ContentCompression:       types.ObjectNull(contentCompressionAttrTypes),
		AccessFilter:             types.ObjectNull(accessFilterAttrTypes),
		WebP:                     types.Int64Null(),
		TLSVersions:              types.ListNull(types.StringType),
		DefaultHost:              types.StringNull(),
	}
}

func TestApplyPlanAccessFilter(t *testing.T) {
	ctx := context.Background()

	geo := emptyFilterModel()
	geo.Geo = &CDNFilterListRulesModel{Allow: nullSet(), AllowStatusCode: types.Int64Null(), Deny: setOf("CN"), DenyStatusCode: types.Int64Value(403)}

	t.Run("changed filter is sent with filter_set", func(t *testing.T) {
		mc := newMockClient().On(cdnTestPath, "filter_set", map[string]interface{}{})
		r := &CDNResource{client: mc}
		plan, state := nullCDNModel(), nullCDNModel()
		plan.AccessFilter = filterObj(t, geo)
		state.AccessFilter = filterObj(t, emptyFilterModel())

		var d diag.Diagnostics
		if !r.applyPlanToAPI(ctx, cdnTestPath, plan, state, &d) {
			t.Fatal(d)
		}
		calls := mc.CallsFor(cdnTestPath, "filter_set")
		if len(calls) != 1 {
			t.Fatalf("filter_set calls = %d, want 1", len(calls))
		}
		b, _ := json.Marshal(calls[0].Params)
		want := `{"skip":null,"geo":{"allow":[],"allow_rule_blocking_http_status_code":null,"deny":["CN"],"deny_rule_blocking_http_status_code":403},"ip":null,"uri":null,"user_agent":null,"referer":null,"method":null}`
		if string(b) != want {
			t.Errorf("params = %s\nwant     %s", b, want)
		}
	})

	t.Run("on create (no prior state) filter_set is called", func(t *testing.T) {
		mc := newMockClient().On(cdnTestPath, "filter_set", map[string]interface{}{})
		r := &CDNResource{client: mc}
		plan := nullCDNModel()
		plan.AccessFilter = filterObj(t, geo)

		var d diag.Diagnostics
		if !r.applyPlanToAPI(ctx, cdnTestPath, plan, CDNModel{}, &d) {
			t.Fatal(d)
		}
		if n := len(mc.CallsFor(cdnTestPath, "filter_set")); n != 1 {
			t.Errorf("filter_set calls = %d, want 1", n)
		}
	})

	t.Run("unchanged filter is not sent", func(t *testing.T) {
		mc := newMockClient()
		r := &CDNResource{client: mc}
		plan, state := nullCDNModel(), nullCDNModel()
		plan.AccessFilter = filterObj(t, geo)
		state.AccessFilter = filterObj(t, geo)

		var d diag.Diagnostics
		if !r.applyPlanToAPI(ctx, cdnTestPath, plan, state, &d) {
			t.Fatal(d)
		}
		if n := len(mc.Called()); n != 0 {
			t.Errorf("unexpected API calls: %v", mc.Called())
		}
	})

	t.Run("removed from config: filter is left untouched", func(t *testing.T) {
		mc := newMockClient()
		r := &CDNResource{client: mc}
		plan, state := nullCDNModel(), nullCDNModel()
		state.AccessFilter = filterObj(t, geo)

		var d diag.Diagnostics
		if !r.applyPlanToAPI(ctx, cdnTestPath, plan, state, &d) {
			t.Fatal(d)
		}
		if n := len(mc.Called()); n != 0 {
			t.Errorf("unexpected API calls: %v", mc.Called())
		}
	})

	t.Run("unknown filter is not sent", func(t *testing.T) {
		mc := newMockClient()
		r := &CDNResource{client: mc}
		plan, state := nullCDNModel(), nullCDNModel()
		plan.AccessFilter = types.ObjectUnknown(accessFilterAttrTypes)
		state.AccessFilter = filterObj(t, geo)

		var d diag.Diagnostics
		if !r.applyPlanToAPI(ctx, cdnTestPath, plan, state, &d) {
			t.Fatal(d)
		}
		if n := len(mc.Called()); n != 0 {
			t.Errorf("unexpected API calls: %v", mc.Called())
		}
	})
}

// ---------------------------------------------------------------------------
// tfsdk helpers
// ---------------------------------------------------------------------------

var basetypesObjectAsOptions = basetypes.ObjectAsOptions{}

// tfsdkStateFromValues builds a state for schema s from attribute values.
func tfsdkStateFromValues(t *testing.T, s *schema.Schema, values map[string]attr.Value) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	objType := s.Type().(basetypes.ObjectType)
	obj, d := types.ObjectValue(objType.AttrTypes, values)
	if d.HasError() {
		t.Fatal(d)
	}
	raw, err := obj.ToTerraformValue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return tfsdk.State{Schema: *s, Raw: raw}
}

// emptyTfsdkState returns a null state for schema s.
func emptyTfsdkState(t *testing.T, s schema.Schema) tfsdk.State {
	t.Helper()
	return tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(context.Background()), nil)}
}
