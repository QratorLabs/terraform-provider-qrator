package provider

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// svcCompositeKey
// ---------------------------------------------------------------------------

func TestSvcCompositeKey_AllTypes(t *testing.T) {
	tests := []struct {
		name  string
		entry apiServiceEntry
		want  string
	}{
		{"dns", apiServiceEntry{Type: "dns", Port: int64Ptr(53)}, "dns:53"},
		{"http", apiServiceEntry{Type: "http", Port: int64Ptr(80)}, "http:80"},
		{"icmp", apiServiceEntry{Type: "icmp"}, "icmp"},
		{"nat", apiServiceEntry{Type: "nat", Proto: "udp", Port: int64Ptr(53)}, "nat:udp:53"},
		{"any-ie", apiServiceEntry{Type: "any-ingress-egress"}, "any-ingress-egress"},
		{"tcp-ie", apiServiceEntry{Type: "tcp-ingress-egress"}, "tcp-ingress-egress"},
		{"tcp-egress", apiServiceEntry{Type: "tcp-egress"}, "tcp-egress"},
		{"frag-ie", apiServiceEntry{Type: "frag-ingress-egress"}, "frag-ingress-egress"},
		{"unknown", apiServiceEntry{Type: "unknown"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := svcCompositeKey(&tt.entry)
			if got != tt.want {
				t.Errorf("svcCompositeKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSvcCompositeKey_ProtoFloat64(t *testing.T) {
	// JSON unmarshals numbers as float64
	entry := apiServiceEntry{Type: "proto-ingress-egress", Proto: float64(17)}
	got := svcCompositeKey(&entry)
	if got != "proto-ingress-egress:17" {
		t.Errorf("svcCompositeKey(proto float64) = %q, want proto-ingress-egress:17", got)
	}
}

func TestSvcCompositeKey_ProtoInt64(t *testing.T) {
	entry := apiServiceEntry{Type: "proto-ingress-egress", Proto: int64(6)}
	got := svcCompositeKey(&entry)
	if got != "proto-ingress-egress:6" {
		t.Errorf("svcCompositeKey(proto int64) = %q, want proto-ingress-egress:6", got)
	}
}

// ---------------------------------------------------------------------------
// Round-trip: model → API → model for all 9 types
// ---------------------------------------------------------------------------

func TestSvcDNS_RoundTrip(t *testing.T) {
	m := ServiceDNSModel{ID: types.Int64Value(1), Port: types.Int64Value(53), DefaultDrop: types.BoolNull()}
	api := svcDNSModelToAPI(&m)
	if api.Type != "dns" {
		t.Errorf("Type = %q, want dns", api.Type)
	}
	back := apiToSvcDNSModel(&api)
	if back.Port.ValueInt64() != 53 {
		t.Errorf("Port = %d, want 53", back.Port.ValueInt64())
	}
}

func TestSvcHTTP_RoundTrip(t *testing.T) {
	m := ServiceHTTPModel{
		ID:          types.Int64Value(2),
		Port:        types.Int64Value(443),
		SSL:         types.BoolValue(true),
		HTTP2:       types.BoolValue(true),
		DefaultDrop: types.BoolNull(),
		Upstream: &ServiceHTTPUpstreamModel{
			SSL:         types.BoolValue(true),
			SNIName:     types.StringNull(),
			SNIOverride: types.BoolValue(false),
		},
	}
	api := svcHTTPModelToAPI(&m)
	if api.Type != "http" {
		t.Errorf("Type = %q, want http", api.Type)
	}
	back := apiToSvcHTTPModel(&api)
	if back.Port.ValueInt64() != 443 {
		t.Errorf("Port = %d, want 443", back.Port.ValueInt64())
	}
	if back.Upstream == nil || !back.Upstream.SSL.ValueBool() {
		t.Error("Upstream.SSL should be true")
	}
}

func TestSvcICMP_RoundTrip(t *testing.T) {
	rl := int64(80000)
	m := ServiceICMPModel{ID: types.Int64Value(3), DefaultDrop: types.BoolNull(), RateLimit: types.Int64Value(rl)}
	api := svcICMPModelToAPI(&m)
	if api.Type != "icmp" {
		t.Errorf("Type = %q, want icmp", api.Type)
	}
	if api.RateLimit == nil || *api.RateLimit != 80000 {
		t.Errorf("RateLimit = %v, want 80000", api.RateLimit)
	}
	back := apiToSvcICMPModel(&api)
	if back.RateLimit.ValueInt64() != 80000 {
		t.Errorf("RateLimit = %d, want 80000", back.RateLimit.ValueInt64())
	}
}

func TestSvcNAT_RoundTrip(t *testing.T) {
	m := ServiceNATModel{
		ID: types.Int64Value(4), Port: types.Int64Value(25), Proto: types.StringValue("tcp"),
		DefaultDrop: types.BoolNull(), DropAmp: types.BoolNull(), RateLimit: types.Int64Null(),
	}
	api := svcNATModelToAPI(&m)
	if api.Type != "nat" {
		t.Errorf("Type = %q, want nat", api.Type)
	}
	back := apiToSvcNATModel(&api)
	if back.Port.ValueInt64() != 25 {
		t.Errorf("Port = %d, want 25", back.Port.ValueInt64())
	}
	if back.Proto.ValueString() != "tcp" {
		t.Errorf("Proto = %q, want tcp", back.Proto.ValueString())
	}
}

func TestSvcAnyIE_RoundTrip(t *testing.T) {
	m := ServiceAnyIEModel{ID: types.Int64Value(5), DefaultDrop: types.BoolNull(), DropAmp: types.BoolValue(true), RateLimit: types.Int64Value(80000)}
	api := svcAnyIEModelToAPI(&m)
	if api.Type != "any-ingress-egress" {
		t.Errorf("Type = %q, want any-ingress-egress", api.Type)
	}
	back := apiToSvcAnyIEModel(&api)
	if !back.DropAmp.ValueBool() {
		t.Error("DropAmp should be true")
	}
	if back.RateLimit.ValueInt64() != 80000 {
		t.Errorf("RateLimit = %d, want 80000", back.RateLimit.ValueInt64())
	}
}

func TestSvcProtoIE_RoundTrip(t *testing.T) {
	m := ServiceProtoIEModel{ID: types.Int64Value(6), Proto: types.Int64Value(17), DefaultDrop: types.BoolNull(), DropAmp: types.BoolNull(), RateLimit: types.Int64Null()}
	api := svcProtoIEModelToAPI(&m)
	if api.Type != "proto-ingress-egress" {
		t.Errorf("Type = %q, want proto-ingress-egress", api.Type)
	}

	// Simulate JSON round-trip (proto becomes float64)
	raw, _ := json.Marshal(api)
	var roundTripped apiServiceEntry
	json.Unmarshal(raw, &roundTripped)

	back := apiToSvcProtoIEModel(&roundTripped)
	if back.Proto.ValueInt64() != 17 {
		t.Errorf("Proto = %d, want 17", back.Proto.ValueInt64())
	}
}

func TestSvcTCPIE_RoundTrip(t *testing.T) {
	m := ServiceTCPIEModel{ID: types.Int64Value(7), DefaultDrop: types.BoolNull()}
	api := svcTCPIEModelToAPI(&m)
	if api.Type != "tcp-ingress-egress" {
		t.Errorf("Type = %q, want tcp-ingress-egress", api.Type)
	}
	back := apiToSvcTCPIEModel(&api)
	if back.DefaultDrop.IsNull() != true {
		t.Errorf("DefaultDrop should be null")
	}
}

func TestSvcTCPEgress_RoundTrip(t *testing.T) {
	m := ServiceTCPEModel{ID: types.Int64Value(8), DefaultDrop: types.BoolValue(false)}
	api := svcTCPEgressModelToAPI(&m)
	if api.Type != "tcp-egress" {
		t.Errorf("Type = %q, want tcp-egress", api.Type)
	}
	back := apiToSvcTCPEgressModel(&api)
	if back.DefaultDrop.ValueBool() {
		t.Error("DefaultDrop should be false")
	}
}

func TestSvcFragIE_RoundTrip(t *testing.T) {
	m := ServiceFragIEModel{ID: types.Int64Value(9), DefaultDrop: types.BoolNull(), RateLimit: types.Int64Value(80000)}
	api := svcFragIEModelToAPI(&m)
	if api.Type != "frag-ingress-egress" {
		t.Errorf("Type = %q, want frag-ingress-egress", api.Type)
	}
	back := apiToSvcFragIEModel(&api)
	if back.RateLimit.ValueInt64() != 80000 {
		t.Errorf("RateLimit = %d, want 80000", back.RateLimit.ValueInt64())
	}
}

// ---------------------------------------------------------------------------
// sortByID
// ---------------------------------------------------------------------------

func TestSortByID(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var s []ServiceDNSModel
		sortByID(s, func(e *ServiceDNSModel) int64 { return e.ID.ValueInt64() })
		if len(s) != 0 {
			t.Error("expected empty")
		}
	})

	t.Run("already sorted", func(t *testing.T) {
		s := []ServiceDNSModel{
			{ID: types.Int64Value(1), Port: types.Int64Value(53)},
			{ID: types.Int64Value(2), Port: types.Int64Value(5353)},
		}
		sortByID(s, func(e *ServiceDNSModel) int64 { return e.ID.ValueInt64() })
		if s[0].ID.ValueInt64() != 1 || s[1].ID.ValueInt64() != 2 {
			t.Errorf("order should be preserved: [%d, %d]", s[0].ID.ValueInt64(), s[1].ID.ValueInt64())
		}
	})

	t.Run("reversed", func(t *testing.T) {
		s := []ServiceDNSModel{
			{ID: types.Int64Value(200), Port: types.Int64Value(5353)},
			{ID: types.Int64Value(100), Port: types.Int64Value(53)},
		}
		sortByID(s, func(e *ServiceDNSModel) int64 { return e.ID.ValueInt64() })
		if s[0].ID.ValueInt64() != 100 {
			t.Errorf("first should be 100, got %d", s[0].ID.ValueInt64())
		}
		if s[1].ID.ValueInt64() != 200 {
			t.Errorf("second should be 200, got %d", s[1].ID.ValueInt64())
		}
	})
}

// ---------------------------------------------------------------------------
// buildSvcServiceList / apiToSvcServicesModel
// ---------------------------------------------------------------------------

func TestBuildSvcServiceList_AllTypes(t *testing.T) {
	m := &ServiceServicesResourceModel{
		ServiceID: types.Int64Value(1),
		DNS:       []ServiceDNSModel{{Port: types.Int64Value(53), DefaultDrop: types.BoolNull()}},
		HTTP:      []ServiceHTTPModel{{Port: types.Int64Value(80), SSL: types.BoolValue(false), HTTP2: types.BoolValue(false), DefaultDrop: types.BoolNull(), Upstream: &ServiceHTTPUpstreamModel{SSL: types.BoolValue(false), SNIName: types.StringNull(), SNIOverride: types.BoolValue(false)}}},
		ICMP:      []ServiceICMPModel{{DefaultDrop: types.BoolNull(), RateLimit: types.Int64Null()}},
		NAT:       []ServiceNATModel{{Port: types.Int64Value(25), Proto: types.StringValue("tcp"), DefaultDrop: types.BoolNull(), DropAmp: types.BoolNull(), RateLimit: types.Int64Null()}},
		AnyIngressEgress:   []ServiceAnyIEModel{{DefaultDrop: types.BoolNull(), DropAmp: types.BoolNull(), RateLimit: types.Int64Null()}},
		ProtoIngressEgress: []ServiceProtoIEModel{{Proto: types.Int64Value(17), DefaultDrop: types.BoolNull(), DropAmp: types.BoolNull(), RateLimit: types.Int64Null()}},
		TCPIngressEgress:   []ServiceTCPIEModel{{DefaultDrop: types.BoolNull()}},
		TCPEgress:          []ServiceTCPEModel{{DefaultDrop: types.BoolNull()}},
		FragIngressEgress:  []ServiceFragIEModel{{DefaultDrop: types.BoolNull(), RateLimit: types.Int64Null()}},
	}

	entries := buildSvcServiceList(m)
	if len(entries) != 9 {
		t.Errorf("buildSvcServiceList() returned %d entries, want 9", len(entries))
	}
}

func TestApiToSvcServicesModel_AllTypes(t *testing.T) {
	entries := []apiServiceEntry{
		{ID: int64Ptr(1), Type: "dns", Port: int64Ptr(53)},
		{ID: int64Ptr(2), Type: "http", Port: int64Ptr(80), Upstream: rawMsg(apiServiceHTTPUpstream{SSL: false})},
		{ID: int64Ptr(3), Type: "icmp"},
		{ID: int64Ptr(4), Type: "nat", Port: int64Ptr(25), Proto: "tcp"},
		{ID: int64Ptr(5), Type: "any-ingress-egress"},
		{ID: int64Ptr(6), Type: "proto-ingress-egress", Proto: float64(17)},
		{ID: int64Ptr(7), Type: "tcp-ingress-egress"},
		{ID: int64Ptr(8), Type: "tcp-egress"},
		{ID: int64Ptr(9), Type: "frag-ingress-egress"},
	}

	m := &ServiceServicesResourceModel{}
	apiToSvcServicesModel(entries, m)

	if len(m.DNS) != 1 {
		t.Errorf("DNS = %d, want 1", len(m.DNS))
	}
	if len(m.HTTP) != 1 {
		t.Errorf("HTTP = %d, want 1", len(m.HTTP))
	}
	if len(m.ICMP) != 1 {
		t.Errorf("ICMP = %d, want 1", len(m.ICMP))
	}
	if len(m.NAT) != 1 {
		t.Errorf("NAT = %d, want 1", len(m.NAT))
	}
	if len(m.AnyIngressEgress) != 1 {
		t.Errorf("AnyIE = %d, want 1", len(m.AnyIngressEgress))
	}
	if len(m.ProtoIngressEgress) != 1 {
		t.Errorf("ProtoIE = %d, want 1", len(m.ProtoIngressEgress))
	}
	if len(m.TCPIngressEgress) != 1 {
		t.Errorf("TCPIE = %d, want 1", len(m.TCPIngressEgress))
	}
	if len(m.TCPEgress) != 1 {
		t.Errorf("TCPEgress = %d, want 1", len(m.TCPEgress))
	}
	if len(m.FragIngressEgress) != 1 {
		t.Errorf("FragIE = %d, want 1", len(m.FragIngressEgress))
	}
}

// ---------------------------------------------------------------------------
// injectSvcIDsFromState
// ---------------------------------------------------------------------------

func TestInjectSvcIDsFromState_MatchesByKey(t *testing.T) {
	state := &ServiceServicesResourceModel{
		DNS:  []ServiceDNSModel{{ID: types.Int64Value(10), Port: types.Int64Value(53)}},
		HTTP: []ServiceHTTPModel{{ID: types.Int64Value(20), Port: types.Int64Value(80)}},
		ICMP: []ServiceICMPModel{{ID: types.Int64Value(30)}},
	}

	entries := []apiServiceEntry{
		{Type: "http", Port: int64Ptr(80)},
		{Type: "dns", Port: int64Ptr(53)},
		{Type: "icmp"},
	}

	injectSvcIDsFromState(entries, state)

	if entries[0].ID == nil || *entries[0].ID != 20 {
		t.Errorf("http entry ID = %v, want 20", entries[0].ID)
	}
	if entries[1].ID == nil || *entries[1].ID != 10 {
		t.Errorf("dns entry ID = %v, want 10", entries[1].ID)
	}
	if entries[2].ID == nil || *entries[2].ID != 30 {
		t.Errorf("icmp entry ID = %v, want 30", entries[2].ID)
	}
}

func TestInjectSvcIDsFromState_NilState(t *testing.T) {
	entries := []apiServiceEntry{{Type: "dns", Port: int64Ptr(53)}}
	injectSvcIDsFromState(entries, nil)
	if entries[0].ID != nil {
		t.Error("nil state should leave ID as nil")
	}
}
