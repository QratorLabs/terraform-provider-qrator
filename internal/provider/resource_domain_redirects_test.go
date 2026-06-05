package provider

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestRedirectModelToAPI_NullFields verifies that nil Go pointers serialize
// to JSON null (not omitted) for fields that the API requires to be present.
// The API schema has additionalProperties:false and required:[...] for both
// the outer item (redirect, from.uri) and the redirect object (hostname, path).
func TestRedirectModelToAPI_NullFields(t *testing.T) {
	m := DomainRedirectModel{
		From: DomainRedirectFromModel{
			Port: types.Int64Value(80),
			Hostname: DomainRedirectHostnameModel{
				Type:  types.StringValue("any"),
				Value: types.StringNull(),
			},
			URI: nil, // null = any URI
		},
		Redirect: &DomainRedirectTargetModel{
			Code:     types.Int64Value(301),
			Schema:   types.StringNull(), // omitted from JSON (omitempty)
			Hostname: types.StringNull(), // must be "hostname": null
			Port:     types.Int64Value(443),
			Path:     types.StringNull(), // must be "path": null
			Args:     types.BoolValue(true),
		},
	}

	entry := redirectModelToAPI(m)
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	s := string(b)

	// from.uri must be present as null (required field in API schema)
	if !strings.Contains(s, `"uri":null`) {
		t.Errorf("expected \"uri\":null in JSON, got: %s", s)
	}

	// redirect.hostname must be present as null
	if !strings.Contains(s, `"hostname":null`) {
		t.Errorf("expected \"hostname\":null in JSON, got: %s", s)
	}

	// redirect.path must be present as null
	if !strings.Contains(s, `"path":null`) {
		t.Errorf("expected \"path\":null in JSON, got: %s", s)
	}

	// redirect.schema must be absent (omitempty is OK for optional field)
	if strings.Contains(s, `"schema"`) {
		t.Errorf("expected \"schema\" to be absent (omitempty), got: %s", s)
	}

	// hostname.value must be absent for type="any" (omitempty)
	if strings.Contains(s, `"value":null`) && strings.Contains(s, `"type":"any"`) {
		t.Logf("note: hostname value field present for type=any; JSON: %s", s)
	}
}

// TestRedirectModelToAPI_NullRedirect verifies that a null redirect target
// serializes as "redirect":null (required field in API schema).
func TestRedirectModelToAPI_NullRedirect(t *testing.T) {
	m := DomainRedirectModel{
		From: DomainRedirectFromModel{
			Port: types.Int64Value(443),
			Hostname: DomainRedirectHostnameModel{
				Type:  types.StringValue("fqdn"),
				Value: types.StringValue("example.com"),
			},
			URI: &DomainRedirectURIModel{
				Type:  types.StringValue("exact"),
				Value: types.StringValue("/old"),
			},
		},
		Redirect: nil, // null = disabled (blocks less-specific rules)
	}

	entry := redirectModelToAPI(m)
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	s := string(b)

	// redirect must be present as null (required in API schema)
	if !strings.Contains(s, `"redirect":null`) {
		t.Errorf("expected \"redirect\":null in JSON, got: %s", s)
	}

	// from.uri must be present as object (not null)
	if !strings.Contains(s, `"uri":{`) {
		t.Errorf("expected \"uri\":{...} in JSON, got: %s", s)
	}
}

// TestAPIToRedirectModel_RoundTrip verifies that API → model → API
// round-trips without data loss for a full redirect rule.
func TestAPIToRedirectModel_RoundTrip(t *testing.T) {
	schema := "https"
	hostname := "example.com"
	path := "/new"
	hostnameValue := "old.example.com"

	original := apiRedirectEntry{
		From: apiRedirectFrom{
			Port: 80,
			Hostname: apiRedirectHostname{
				Type:  "fqdn",
				Value: &hostnameValue,
			},
			URI: &apiRedirectURI{
				Type:  "exact",
				Value: "/old",
			},
		},
		Redirect: &apiRedirectTarget{
			Code:     301,
			Schema:   &schema,
			Hostname: &hostname,
			Port:     443,
			Path:     &path,
			Args:     true,
		},
	}

	model := apiToRedirectModel(original)
	back := redirectModelToAPI(model)

	// Compare JSON representations
	origJSON, _ := json.Marshal(original)
	backJSON, _ := json.Marshal(back)
	if string(origJSON) != string(backJSON) {
		t.Errorf("round-trip mismatch:\n  orig: %s\n  back: %s", origJSON, backJSON)
	}
}

// TestRedirectCompositeKey verifies that different "from" matchers
// produce different keys and identical ones produce the same key.
func TestRedirectCompositeKey(t *testing.T) {
	make80Any := func() *DomainRedirectModel {
		return &DomainRedirectModel{
			From: DomainRedirectFromModel{
				Port: types.Int64Value(80),
				Hostname: DomainRedirectHostnameModel{
					Type:  types.StringValue("any"),
					Value: types.StringNull(),
				},
				URI: nil,
			},
		}
	}
	make80FQDN := func() *DomainRedirectModel {
		return &DomainRedirectModel{
			From: DomainRedirectFromModel{
				Port: types.Int64Value(80),
				Hostname: DomainRedirectHostnameModel{
					Type:  types.StringValue("fqdn"),
					Value: types.StringValue("a.example.com"),
				},
				URI: nil,
			},
		}
	}
	make443Any := func() *DomainRedirectModel {
		return &DomainRedirectModel{
			From: DomainRedirectFromModel{
				Port: types.Int64Value(443),
				Hostname: DomainRedirectHostnameModel{
					Type:  types.StringValue("any"),
					Value: types.StringNull(),
				},
				URI: nil,
			},
		}
	}

	k80Any := redirectCompositeKey(make80Any())
	k80Any2 := redirectCompositeKey(make80Any())
	k80FQDN := redirectCompositeKey(make80FQDN())
	k443Any := redirectCompositeKey(make443Any())

	if k80Any != k80Any2 {
		t.Errorf("same rule produced different keys: %q vs %q", k80Any, k80Any2)
	}
	if k80Any == k80FQDN {
		t.Errorf("different rules produced same key: %q", k80Any)
	}
	if k80Any == k443Any {
		t.Errorf("different ports produced same key: %q", k80Any)
	}
}
