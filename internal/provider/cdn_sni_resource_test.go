package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	tftypes "github.com/hashicorp/terraform-plugin-go/tftypes"
)

// newCDNSNIState builds a properly initialised null tfsdk.State for CDNSNIResource.
func newCDNSNIState(t *testing.T) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	var schemaResp resource.SchemaResponse
	(&CDNSNIResource{}).Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	sniObjType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"host":        tftypes.String,
		"certificate": tftypes.Number,
	}}
	stateType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"domain_id": tftypes.Number,
		"entries":   tftypes.List{ElementType: sniObjType},
	}}
	raw := tftypes.NewValue(stateType, map[string]tftypes.Value{
		"domain_id": tftypes.NewValue(tftypes.Number, nil),
		"entries":   tftypes.NewValue(tftypes.List{ElementType: sniObjType}, nil),
	})
	return tfsdk.State{Schema: schemaResp.Schema, Raw: raw}
}

var cdnSNIEntryAttrTypes = map[string]attr.Type{
	"host":        types.StringType,
	"certificate": types.Int64Type,
}

// ---------------------------------------------------------------------------
// entriesToAPI
// ---------------------------------------------------------------------------

func TestCDNSNIEntriesToAPI(t *testing.T) {
	ctx := context.Background()
	r := &CDNSNIResource{}

	t.Run("with certificate", func(t *testing.T) {
		certID := int64(7)
		list, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: cdnSNIEntryAttrTypes}, []CDNSNIEntryModel{
			{Host: types.StringValue("cdn.example.com"), Certificate: types.Int64Value(certID)},
		})
		if d.HasError() {
			t.Fatal(d)
		}
		params, err := r.entriesToAPI(ctx, list)
		if err != nil {
			t.Fatal(err)
		}
		if len(params) != 1 {
			t.Fatalf("len = %d, want 1", len(params))
		}
		if params[0]["host"] != "cdn.example.com" {
			t.Errorf("host = %v", params[0]["host"])
		}
		if params[0]["certificate"] != certID {
			t.Errorf("certificate = %v, want %d", params[0]["certificate"], certID)
		}
	})

	t.Run("null certificate", func(t *testing.T) {
		list, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: cdnSNIEntryAttrTypes}, []CDNSNIEntryModel{
			{Host: types.StringValue("plain.example.com"), Certificate: types.Int64Null()},
		})
		if d.HasError() {
			t.Fatal(d)
		}
		params, err := r.entriesToAPI(ctx, list)
		if err != nil {
			t.Fatal(err)
		}
		if len(params) != 1 || params[0]["certificate"] != nil {
			t.Errorf("expected nil certificate, got %v", params[0]["certificate"])
		}
	})

	t.Run("empty list", func(t *testing.T) {
		list := types.ListValueMust(types.ObjectType{AttrTypes: cdnSNIEntryAttrTypes}, []attr.Value{})
		params, err := r.entriesToAPI(ctx, list)
		if err != nil || len(params) != 0 {
			t.Errorf("got %v, %v", params, err)
		}
	})
}

// ---------------------------------------------------------------------------
// readAndSetState
// ---------------------------------------------------------------------------

func TestCDNSNIReadAndSetState(t *testing.T) {
	ctx := context.Background()

	t.Run("sets domain_id and entries from API response", func(t *testing.T) {
		certID := int64(7)
		apiResp := []cdnSNIEntry{{Host: "cdn.example.com", Certificate: &certID}}
		mc := newMockClient().On("/request/cdn/42", "sni_get", apiResp)
		r := &CDNSNIResource{client: mc}

		state := newCDNSNIState(t)
		var d diag.Diagnostics
		r.readAndSetState(ctx, 42, nil, &d, &state)
		if d.HasError() {
			t.Fatal(d)
		}

		var domainID types.Int64
		d.Append(state.GetAttribute(ctx, path.Root("domain_id"), &domainID)...)
		if d.HasError() {
			t.Fatal(d)
		}
		if domainID.ValueInt64() != 42 {
			t.Errorf("domain_id = %d, want 42", domainID.ValueInt64())
		}

		var entriesList types.List
		d.Append(state.GetAttribute(ctx, path.Root("entries"), &entriesList)...)
		var entries []CDNSNIEntryModel
		d.Append(entriesList.ElementsAs(ctx, &entries, false)...)
		if d.HasError() {
			t.Fatal(d)
		}
		if len(entries) != 1 || entries[0].Host.ValueString() != "cdn.example.com" {
			t.Errorf("entries = %v", entries)
		}
		if entries[0].Certificate.ValueInt64() != 7 {
			t.Errorf("certificate = %d, want 7", entries[0].Certificate.ValueInt64())
		}
	})

	t.Run("nil certificate in API response stored as null", func(t *testing.T) {
		apiResp := []cdnSNIEntry{{Host: "plain.example.com", Certificate: nil}}
		mc := newMockClient().On("/request/cdn/5", "sni_get", apiResp)
		r := &CDNSNIResource{client: mc}

		state := newCDNSNIState(t)
		var d diag.Diagnostics
		r.readAndSetState(ctx, 5, nil, &d, &state)
		if d.HasError() {
			t.Fatal(d)
		}

		var entriesList types.List
		d.Append(state.GetAttribute(ctx, path.Root("entries"), &entriesList)...)
		var entries []CDNSNIEntryModel
		d.Append(entriesList.ElementsAs(ctx, &entries, false)...)
		if d.HasError() {
			t.Fatal(d)
		}
		if !entries[0].Certificate.IsNull() {
			t.Errorf("expected null certificate, got %v", entries[0].Certificate)
		}
	})

	t.Run("sni_get error adds diagnostic", func(t *testing.T) {
		mc := newMockClient().OnError("/request/cdn/99", "sni_get", fmt.Errorf("api error"))
		r := &CDNSNIResource{client: mc}

		state := newCDNSNIState(t)
		var d diag.Diagnostics
		r.readAndSetState(ctx, 99, nil, &d, &state)
		if !d.HasError() {
			t.Error("expected error diagnostic")
		}
	})

	t.Run("reorders entries by ref order", func(t *testing.T) {
		apiResp := []cdnSNIEntry{
			{Host: "a.example.com", Certificate: nil},
			{Host: "b.example.com", Certificate: nil},
		}
		mc := newMockClient().On("/request/cdn/1", "sni_get", apiResp)
		r := &CDNSNIResource{client: mc}

		// ref order: b first, a second — result should follow ref
		ref := []CDNSNIEntryModel{
			{Host: types.StringValue("b.example.com"), Certificate: types.Int64Null()},
			{Host: types.StringValue("a.example.com"), Certificate: types.Int64Null()},
		}
		state := newCDNSNIState(t)
		var d diag.Diagnostics
		r.readAndSetState(ctx, 1, ref, &d, &state)
		if d.HasError() {
			t.Fatal(d)
		}

		var entriesList types.List
		d.Append(state.GetAttribute(ctx, path.Root("entries"), &entriesList)...)
		var entries []CDNSNIEntryModel
		d.Append(entriesList.ElementsAs(ctx, &entries, false)...)
		if d.HasError() {
			t.Fatal(d)
		}
		if len(entries) != 2 || entries[0].Host.ValueString() != "b.example.com" {
			t.Errorf("expected b first, got %v", entries)
		}
	})

	t.Run("makes sni_get call with correct path", func(t *testing.T) {
		mc := newMockClient().On("/request/cdn/77", "sni_get", []cdnSNIEntry{})
		r := &CDNSNIResource{client: mc}
		state := newCDNSNIState(t)
		var d diag.Diagnostics
		r.readAndSetState(ctx, 77, nil, &d, &state)
		if d.HasError() {
			t.Fatal(d)
		}
		if n := len(mc.CallsFor("/request/cdn/77", "sni_get")); n != 1 {
			t.Errorf("expected 1 sni_get call, got %d", n)
		}
	})
}

// ---------------------------------------------------------------------------
// Delete — verifies sni_set called with empty list
// ---------------------------------------------------------------------------

func TestCDNSNIDeleteAPICall(t *testing.T) {
	ctx := context.Background()

	mc := newMockClient().On("/request/cdn/5", "sni_set", nil)
	r := &CDNSNIResource{client: mc}

	state := newCDNSNIState(t)
	var setDiags diag.Diagnostics
	setDiags.Append(state.SetAttribute(ctx, path.Root("domain_id"), types.Int64Value(5))...)
	if setDiags.HasError() {
		t.Fatal(setDiags)
	}

	var resp resource.DeleteResponse
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}

	calls := mc.CallsFor("/request/cdn/5", "sni_set")
	if len(calls) != 1 {
		t.Fatalf("expected 1 sni_set call, got %d", len(calls))
	}
	params, ok := calls[0].Params.([]interface{})
	if !ok || len(params) != 0 {
		t.Errorf("expected empty list params, got %v (%T)", calls[0].Params, calls[0].Params)
	}
}
