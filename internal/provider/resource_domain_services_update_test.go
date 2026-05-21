package provider

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestDomainServicesUpdate_NewServiceLowerID reproduces:
//
//	"Provider produced inconsistent result after apply"
//	.http[1].http2: was cty.True, but now cty.False
//
// Scenario: the domain has one HTTP service on port=80 (id=167944, http2=false).
// The user adds a new HTTP service on port=443 (ssl=true, http2=true).
//
// The API assigns a lower id (100) to the new service. After services_get,
// sortByID places the new service at index 0 and the existing service at index 1.
//
// Without reorderByPlanOrder the state ends up as:
//
//	http[0] = port=443, http2=true   (new service, got lower id)
//	http[1] = port=80,  http2=false  (existing service)
//
// But the plan says http[1].http2=true (new service was at position 1 in config).
// Terraform reports: .http[1].http2: was cty.True, but now cty.False.
//
// reorderByPlanOrder fixes this by restoring plan order by composite key.
func TestDomainServicesUpdate_NewServiceLowerID(t *testing.T) {
	ctx := context.Background()
	domainID := int64(42)
	apiPath := "/request/domain/42"

	// Plan: existing service at [0], new service at [1].
	planHTTP := []DomainServiceHTTPModel{
		{
			ID: types.Int64Value(167944), Port: types.Int64Value(80),
			SSL: types.BoolValue(false), HTTP2: types.BoolValue(false),
			DefaultDrop:      types.BoolValue(false),
			UpstreamBalancer: types.StringValue("roundrobin"),
			UpstreamWeights:  types.BoolValue(false), UpstreamBackups: types.BoolValue(false),
			UpstreamSSL: types.BoolValue(false), UpstreamSNIName: types.StringNull(), UpstreamSNIOverride: types.BoolNull(),
			Upstreams: []DomainUpstreamServerModel{
				{IP: types.StringValue("34.34.9.77"), DNSRecord: types.StringNull(), Port: types.Int64Value(80), Weight: types.Int64Value(100), Type: types.StringValue("primary"), Name: types.StringValue("infra-prod-ingress:80")},
			},
		},
		{
			ID: types.Int64Null(), Port: types.Int64Value(443),
			SSL: types.BoolValue(true), HTTP2: types.BoolValue(true),
			DefaultDrop:      types.BoolValue(false),
			UpstreamBalancer: types.StringValue("roundrobin"),
			UpstreamWeights:  types.BoolValue(false), UpstreamBackups: types.BoolValue(false),
			UpstreamSSL: types.BoolValue(false), UpstreamSNIName: types.StringNull(), UpstreamSNIOverride: types.BoolValue(false),
			Upstreams: []DomainUpstreamServerModel{
				{IP: types.StringValue("34.34.9.77"), DNSRecord: types.StringNull(), Port: types.Int64Value(443), Weight: types.Int64Value(100), Type: types.StringValue("primary"), Name: types.StringValue("infra-prod-ingress:443")},
			},
		},
	}

	// API returns both services. New service gets lower id=100 so sortByID
	// places it at index 0 — ahead of the existing service (id=167944).
	apiResp, _ := json.Marshal([]apiServiceEntry{
		{
			ID: int64Ptr(100), Type: "http", Port: int64Ptr(443),
			SSL: boolPtrHelper(true), HTTP2: boolPtrHelper(true), DefaultDrop: boolPtrHelper(false),
			Upstream: rawMsg(apiHTTPUpstream{
				Balancer: "roundrobin",
				Upstreams: []apiUpstreamServer{
					{IP: strPtr("34.34.9.77"), Port: 443, Weight: 100, Type: "primary", Name: "infra-prod-ingress:443"},
				},
			}),
		},
		{
			ID: int64Ptr(167944), Type: "http", Port: int64Ptr(80),
			SSL: boolPtrHelper(false), HTTP2: boolPtrHelper(false), DefaultDrop: boolPtrHelper(false),
			Upstream: rawMsg(apiHTTPUpstream{
				Balancer: "roundrobin",
				Upstreams: []apiUpstreamServer{
					{IP: strPtr("34.34.9.77"), Port: 80, Weight: 100, Type: "primary", Name: "infra-prod-ingress:80"},
				},
			}),
		},
	})

	mc := newMockClient().OnRaw(apiPath, "services_get", apiResp)
	r := &DomainServicesResource{client: mc}

	plan := DomainServicesResourceModel{
		DomainID: types.Int64Value(domainID),
		HTTP:     append([]DomainServiceHTTPModel(nil), planHTTP...),
	}
	planHTTPCopy := append([]DomainServiceHTTPModel(nil), planHTTP...)

	if err := r.readAndPopulate(ctx, domainID, &plan); err != nil {
		t.Fatal(err)
	}

	// Without reorderByPlanOrder, plan.HTTP would be sorted by id:
	//   [0] = port=443 (id=100, http2=true)
	//   [1] = port=80  (id=167944, http2=false)
	// Terraform then compares plan[1].http2=true vs state[1].http2=false → error.
	plan.HTTP = reorderByPlanOrder(planHTTPCopy, plan.HTTP, func(e *DomainServiceHTTPModel) string {
		return compositeKeyHTTP(e.Port.ValueInt64())
	})

	if len(plan.HTTP) != 2 {
		t.Fatalf("got %d HTTP entries, want 2", len(plan.HTTP))
	}
	// After reorder: plan order restored — port=80 at [0], port=443 at [1].
	if plan.HTTP[0].Port.ValueInt64() != 80 {
		t.Errorf("HTTP[0].port = %d, want 80", plan.HTTP[0].Port.ValueInt64())
	}
	if plan.HTTP[1].Port.ValueInt64() != 443 {
		t.Errorf("HTTP[1].port = %d, want 443", plan.HTTP[1].Port.ValueInt64())
	}
	if !plan.HTTP[1].HTTP2.ValueBool() {
		t.Errorf("HTTP[1].http2 = false, want true")
	}
}
