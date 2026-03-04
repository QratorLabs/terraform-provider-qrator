package provider

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestParseCacheControl(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"string cdn", `"cdn"`, "cdn", false},
		{"string origin", `"origin"`, "origin", false},
		{"number 21600", `21600`, "21600", false},
		{"number 7200", `7200`, "7200", false},
		{"number 604800", `604800`, "604800", false},
		{"null unmarshals to empty string", `null`, "", false},
		{"empty object", `{}`, "", true},
		{"array", `[]`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCacheControl(json.RawMessage(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCacheControl(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseCacheControl(%s) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCacheControlToAPI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  interface{}
	}{
		{"cdn string", "cdn", "cdn"},
		{"origin string", "origin", "origin"},
		{"numeric 21600", "21600", int64(21600)},
		{"numeric 7200", "7200", int64(7200)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cacheControlToAPI(tt.input)
			switch w := tt.want.(type) {
			case string:
				if g, ok := got.(string); !ok || g != w {
					t.Errorf("cacheControlToAPI(%q) = %v (%T), want %v", tt.input, got, got, tt.want)
				}
			case int64:
				if g, ok := got.(int64); !ok || g != w {
					t.Errorf("cacheControlToAPI(%q) = %v (%T), want %v", tt.input, got, got, tt.want)
				}
			}
		})
	}
}

func TestCheckSuccess(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"successful", `"Successful"`, true},
		{"failed", `"Failed"`, false},
		{"invalid json", `not json`, false},
		{"number", `42`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkSuccess(json.RawMessage(tt.input))
			if got != tt.want {
				t.Errorf("checkSuccess(%s) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCacheErrorEntriesEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []CDNCacheErrorEntryModel
		want bool
	}{
		{"both empty", nil, nil, true},
		{"same entries", []CDNCacheErrorEntryModel{
			{Code: types.Int64Value(502), Timeout: types.Int64Value(5000)},
		}, []CDNCacheErrorEntryModel{
			{Code: types.Int64Value(502), Timeout: types.Int64Value(5000)},
		}, true},
		{"different code", []CDNCacheErrorEntryModel{
			{Code: types.Int64Value(502), Timeout: types.Int64Value(5000)},
		}, []CDNCacheErrorEntryModel{
			{Code: types.Int64Value(503), Timeout: types.Int64Value(5000)},
		}, false},
		{"different timeout", []CDNCacheErrorEntryModel{
			{Code: types.Int64Value(502), Timeout: types.Int64Value(5000)},
		}, []CDNCacheErrorEntryModel{
			{Code: types.Int64Value(502), Timeout: types.Int64Value(10000)},
		}, false},
		{"different length", []CDNCacheErrorEntryModel{
			{Code: types.Int64Value(502), Timeout: types.Int64Value(5000)},
		}, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cacheErrorEntriesEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("cacheErrorEntriesEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBlockedURIEntriesEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []CDNBlockedURIEntryModel
		want bool
	}{
		{"both empty", nil, nil, true},
		{"same", []CDNBlockedURIEntryModel{
			{URI: types.StringValue("/admin"), Code: types.Int64Value(403)},
		}, []CDNBlockedURIEntryModel{
			{URI: types.StringValue("/admin"), Code: types.Int64Value(403)},
		}, true},
		{"different uri", []CDNBlockedURIEntryModel{
			{URI: types.StringValue("/admin"), Code: types.Int64Value(403)},
		}, []CDNBlockedURIEntryModel{
			{URI: types.StringValue("/secret"), Code: types.Int64Value(403)},
		}, false},
		{"different code", []CDNBlockedURIEntryModel{
			{URI: types.StringValue("/admin"), Code: types.Int64Value(403)},
		}, []CDNBlockedURIEntryModel{
			{URI: types.StringValue("/admin"), Code: types.Int64Value(404)},
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := blockedURIEntriesEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("blockedURIEntriesEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}
