package provider

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Composite key tests
// ---------------------------------------------------------------------------

func TestCompositeKeyHTTP(t *testing.T) {
	if got := compositeKeyHTTP(80); got != "http:80" {
		t.Errorf("got %q, want http:80", got)
	}
}

func TestCompositeKeyNAT(t *testing.T) {
	if got := compositeKeyNAT("udp", 53); got != "nat:udp:53" {
		t.Errorf("got %q, want nat:udp:53", got)
	}
}

func TestCompositeKeyNATAll(t *testing.T) {
	if got := compositeKeyNATAll("tcp"); got != "nat-all:tcp" {
		t.Errorf("got %q, want nat-all:tcp", got)
	}
}

func TestCompositeKeyTCPProxy(t *testing.T) {
	if got := compositeKeyTCPProxy(3306); got != "tcpproxy:3306" {
		t.Errorf("got %q, want tcpproxy:3306", got)
	}
}

func TestCompositeKeyWebSocket(t *testing.T) {
	if got := compositeKeyWebSocket(8443); got != "websocket:8443" {
		t.Errorf("got %q, want websocket:8443", got)
	}
}

func TestCompositeKeyFromAPI(t *testing.T) {
	tests := []struct {
		name  string
		entry apiServiceEntry
		want  string
	}{
		{"http", apiServiceEntry{Type: "http", Port: int64Ptr(443)}, "http:443"},
		{"nat", apiServiceEntry{Type: "nat", Proto: "udp", Port: int64Ptr(53)}, "nat:udp:53"},
		{"nat-all", apiServiceEntry{Type: "nat-all", Proto: "tcp"}, "nat-all:tcp"},
		{"tcpproxy", apiServiceEntry{Type: "tcpproxy", Port: int64Ptr(3306)}, "tcpproxy:3306"},
		{"websocket", apiServiceEntry{Type: "websocket", Port: int64Ptr(8443)}, "websocket:8443"},
		{"unknown", apiServiceEntry{Type: "unknown"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compositeKeyFromAPI(&tt.entry)
			if got != tt.want {
				t.Errorf("compositeKeyFromAPI() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Round-trip tests: model → API → model
// ---------------------------------------------------------------------------

func TestHTTPModelToAPI_RoundTrip(t *testing.T) {
	ip := "10.0.0.1"
	model := DomainServiceHTTPModel{
		ID:               types.Int64Value(100),
		Port:             types.Int64Value(443),
		SSL:              types.BoolValue(true),
		HTTP2:            types.BoolValue(true),
		DefaultDrop:      types.BoolNull(),
		UpstreamBalancer: types.StringValue("roundrobin"),
		UpstreamWeights:  types.BoolValue(true),
		UpstreamBackups:  types.BoolValue(false),
		UpstreamSSL:      types.BoolValue(true),
		UpstreamSNIName:  types.StringNull(),
		Upstreams: []DomainUpstreamServerModel{
			{
				IP:        types.StringValue(ip),
				DNSRecord: types.StringNull(),
				Port:      types.Int64Value(8443),
				Weight:    types.Int64Value(100),
				Type:      types.StringValue("primary"),
				Name:      types.StringValue(""),
			},
		},
	}

	api := httpModelToAPI(&model)

	if api.Type != "http" {
		t.Errorf("Type = %q, want http", api.Type)
	}
	if *api.Port != 443 {
		t.Errorf("Port = %d, want 443", *api.Port)
	}

	// Convert back
	back := apiToHTTPModel(&api)

	if back.Port.ValueInt64() != 443 {
		t.Errorf("round-trip Port = %d, want 443", back.Port.ValueInt64())
	}
	if !back.SSL.ValueBool() {
		t.Error("round-trip SSL should be true")
	}
	if back.UpstreamBalancer.ValueString() != "roundrobin" {
		t.Errorf("round-trip UpstreamBalancer = %q, want roundrobin", back.UpstreamBalancer.ValueString())
	}
	if len(back.Upstreams) != 1 {
		t.Fatalf("round-trip upstreams count = %d, want 1", len(back.Upstreams))
	}
	if back.Upstreams[0].Port.ValueInt64() != 8443 {
		t.Errorf("round-trip upstream port = %d, want 8443", back.Upstreams[0].Port.ValueInt64())
	}
}

func TestNATModelToAPI_RoundTrip(t *testing.T) {
	model := DomainServiceNATModel{
		ID:           types.Int64Value(200),
		Port:         types.Int64Value(53),
		Proto:        types.StringValue("udp"),
		DefaultDrop:  types.BoolNull(),
		DropAmp:      types.BoolValue(true),
		RateLimit:    types.Int64Null(),
		UpstreamIP:   types.StringValue("10.0.0.2"),
		UpstreamPort: types.Int64Value(53),
	}

	api := natModelToAPI(&model)

	if api.Type != "nat" {
		t.Errorf("Type = %q, want nat", api.Type)
	}

	back := apiToNATModel(&api)

	if back.Port.ValueInt64() != 53 {
		t.Errorf("round-trip Port = %d, want 53", back.Port.ValueInt64())
	}
	if back.Proto.ValueString() != "udp" {
		t.Errorf("round-trip Proto = %q, want udp", back.Proto.ValueString())
	}
	if back.UpstreamIP.ValueString() != "10.0.0.2" {
		t.Errorf("round-trip UpstreamIP = %q, want 10.0.0.2", back.UpstreamIP.ValueString())
	}
	if back.UpstreamPort.ValueInt64() != 53 {
		t.Errorf("round-trip UpstreamPort = %d, want 53", back.UpstreamPort.ValueInt64())
	}
}

func TestNATAllModelToAPI_RoundTrip(t *testing.T) {
	model := DomainServiceNATAllModel{
		ID:          types.Int64Value(300),
		Proto:       types.StringValue("tcp"),
		DefaultDrop: types.BoolNull(),
		DropAmp:     types.BoolNull(),
		RateLimit:   types.Int64Value(80000),
		UpstreamIP:  types.StringValue("10.0.0.3"),
	}

	api := natAllModelToAPI(&model)
	if api.Type != "nat-all" {
		t.Errorf("Type = %q, want nat-all", api.Type)
	}

	back := apiToNATAllModel(&api)

	if back.Proto.ValueString() != "tcp" {
		t.Errorf("round-trip Proto = %q, want tcp", back.Proto.ValueString())
	}
	if back.UpstreamIP.ValueString() != "10.0.0.3" {
		t.Errorf("round-trip UpstreamIP = %q, want 10.0.0.3", back.UpstreamIP.ValueString())
	}
}

func TestTCPProxyModelToAPI_RoundTrip(t *testing.T) {
	model := DomainServiceTCPProxyModel{
		ID:            types.Int64Value(400),
		Port:          types.Int64Value(3306),
		DefaultDrop:   types.BoolNull(),
		ProxyProtocol: types.Int64Value(2),
		Upstreams: []DomainUpstreamServerModel{
			{
				IP:        types.StringValue("10.0.0.4"),
				DNSRecord: types.StringNull(),
				Port:      types.Int64Value(3306),
				Weight:    types.Int64Value(100),
				Type:      types.StringValue("primary"),
				Name:      types.StringValue("db"),
			},
		},
	}

	api := tcpproxyModelToAPI(&model)
	if api.Type != "tcpproxy" {
		t.Errorf("Type = %q, want tcpproxy", api.Type)
	}
	if api.ProxyProtocol == nil || *api.ProxyProtocol != 2 {
		t.Errorf("ProxyProtocol = %v, want 2", api.ProxyProtocol)
	}

	back := apiToTCPProxyModel(&api)

	if back.Port.ValueInt64() != 3306 {
		t.Errorf("round-trip Port = %d, want 3306", back.Port.ValueInt64())
	}
	if len(back.Upstreams) != 1 {
		t.Fatalf("round-trip upstreams count = %d, want 1", len(back.Upstreams))
	}
	if back.Upstreams[0].IP.ValueString() != "10.0.0.4" {
		t.Errorf("round-trip upstream IP = %q, want 10.0.0.4", back.Upstreams[0].IP.ValueString())
	}
}

func TestWebSocketModelToAPI_RoundTrip(t *testing.T) {
	model := DomainServiceWSModel{
		ID:          types.Int64Value(500),
		Port:        types.Int64Value(8443),
		SSL:         types.BoolValue(true),
		DefaultDrop: types.BoolNull(),
		UpstreamSSL: types.BoolValue(true),
		Upstreams: []DomainUpstreamServerModel{
			{
				IP:        types.StringValue("10.0.0.5"),
				DNSRecord: types.StringNull(),
				Port:      types.Int64Value(8443),
				Weight:    types.Int64Value(100),
				Type:      types.StringValue("primary"),
				Name:      types.StringValue(""),
			},
		},
	}

	api := websocketModelToAPI(&model)
	if api.Type != "websocket" {
		t.Errorf("Type = %q, want websocket", api.Type)
	}

	back := apiToWSModel(&api)

	if back.Port.ValueInt64() != 8443 {
		t.Errorf("round-trip Port = %d, want 8443", back.Port.ValueInt64())
	}
	if !back.UpstreamSSL.ValueBool() {
		t.Error("round-trip UpstreamSSL should be true")
	}
	if len(back.Upstreams) != 1 {
		t.Fatalf("round-trip upstreams count = %d, want 1", len(back.Upstreams))
	}
}

// ---------------------------------------------------------------------------
// buildServiceList / apiToServicesModel
// ---------------------------------------------------------------------------

func TestBuildServiceList_AllTypes(t *testing.T) {
	m := &DomainServicesResourceModel{
		DomainID: types.Int64Value(1),
		HTTP: []DomainServiceHTTPModel{
			{
				Port:             types.Int64Value(80),
				SSL:              types.BoolValue(false),
				HTTP2:            types.BoolValue(false),
				DefaultDrop:      types.BoolNull(),
				UpstreamBalancer: types.StringValue("roundrobin"),
				UpstreamWeights:  types.BoolValue(false),
				UpstreamBackups:  types.BoolValue(false),
				UpstreamSSL:      types.BoolValue(false),
				Upstreams: []DomainUpstreamServerModel{
					{IP: types.StringValue("1.1.1.1"), DNSRecord: types.StringNull(), Port: types.Int64Value(80), Weight: types.Int64Value(100), Type: types.StringValue("primary"), Name: types.StringValue("")},
				},
			},
		},
		NAT: []DomainServiceNATModel{
			{Port: types.Int64Value(53), Proto: types.StringValue("udp"), DefaultDrop: types.BoolNull(), DropAmp: types.BoolNull(), RateLimit: types.Int64Null(), UpstreamIP: types.StringValue("2.2.2.2"), UpstreamPort: types.Int64Value(53)},
		},
		NATAll: []DomainServiceNATAllModel{
			{Proto: types.StringValue("tcp"), DefaultDrop: types.BoolNull(), DropAmp: types.BoolNull(), RateLimit: types.Int64Null(), UpstreamIP: types.StringValue("3.3.3.3")},
		},
		TCPProxy: []DomainServiceTCPProxyModel{
			{Port: types.Int64Value(3306), DefaultDrop: types.BoolNull(), ProxyProtocol: types.Int64Null(), Upstreams: []DomainUpstreamServerModel{
				{IP: types.StringValue("4.4.4.4"), DNSRecord: types.StringNull(), Port: types.Int64Value(3306), Weight: types.Int64Value(100), Type: types.StringValue("primary"), Name: types.StringValue("")},
			}},
		},
		WebSocket: []DomainServiceWSModel{
			{Port: types.Int64Value(8443), SSL: types.BoolValue(true), DefaultDrop: types.BoolNull(), UpstreamSSL: types.BoolValue(true), Upstreams: []DomainUpstreamServerModel{
				{IP: types.StringValue("5.5.5.5"), DNSRecord: types.StringNull(), Port: types.Int64Value(8443), Weight: types.Int64Value(100), Type: types.StringValue("primary"), Name: types.StringValue("")},
			}},
		},
	}

	entries := buildServiceList(m)
	if len(entries) != 5 {
		t.Errorf("buildServiceList() returned %d entries, want 5", len(entries))
	}

	typeCount := make(map[string]int)
	for _, e := range entries {
		typeCount[e.Type]++
	}
	for _, tp := range []string{"http", "nat", "nat-all", "tcpproxy", "websocket"} {
		if typeCount[tp] != 1 {
			t.Errorf("expected 1 %s entry, got %d", tp, typeCount[tp])
		}
	}
}

func TestBuildServiceList_Empty(t *testing.T) {
	m := &DomainServicesResourceModel{DomainID: types.Int64Value(1)}
	entries := buildServiceList(m)
	if len(entries) != 0 {
		t.Errorf("buildServiceList(empty) returned %d entries, want 0", len(entries))
	}
}

func TestApiToServicesModel_SortsByID(t *testing.T) {
	entries := []apiServiceEntry{
		{ID: int64Ptr(200), Type: "http", Port: int64Ptr(443), Upstream: rawMsg(apiHTTPUpstream{Balancer: "roundrobin", Upstreams: []apiUpstreamServer{}})},
		{ID: int64Ptr(100), Type: "http", Port: int64Ptr(80), Upstream: rawMsg(apiHTTPUpstream{Balancer: "roundrobin", Upstreams: []apiUpstreamServer{}})},
	}

	m := &DomainServicesResourceModel{}
	apiToServicesModel(entries, m)

	if len(m.HTTP) != 2 {
		t.Fatalf("expected 2 HTTP entries, got %d", len(m.HTTP))
	}
	if m.HTTP[0].ID.ValueInt64() != 100 {
		t.Errorf("first HTTP entry ID = %d, want 100 (sorted)", m.HTTP[0].ID.ValueInt64())
	}
	if m.HTTP[1].ID.ValueInt64() != 200 {
		t.Errorf("second HTTP entry ID = %d, want 200 (sorted)", m.HTTP[1].ID.ValueInt64())
	}
}

// ---------------------------------------------------------------------------
// injectIDsFromState
// ---------------------------------------------------------------------------

func TestInjectIDsFromState_MatchesByKey(t *testing.T) {
	state := &DomainServicesResourceModel{
		HTTP: []DomainServiceHTTPModel{
			{ID: types.Int64Value(100), Port: types.Int64Value(80)},
			{ID: types.Int64Value(200), Port: types.Int64Value(443)},
		},
	}

	entries := []apiServiceEntry{
		{Type: "http", Port: int64Ptr(443)},
		{Type: "http", Port: int64Ptr(80)},
	}

	injectIDsFromState(entries, state)

	if entries[0].ID == nil || *entries[0].ID != 200 {
		t.Errorf("entries[0] (port 443) ID = %v, want 200", entries[0].ID)
	}
	if entries[1].ID == nil || *entries[1].ID != 100 {
		t.Errorf("entries[1] (port 80) ID = %v, want 100", entries[1].ID)
	}
}

func TestInjectIDsFromState_NewEntries(t *testing.T) {
	state := &DomainServicesResourceModel{
		HTTP: []DomainServiceHTTPModel{
			{ID: types.Int64Value(100), Port: types.Int64Value(80)},
		},
	}

	entries := []apiServiceEntry{
		{Type: "http", Port: int64Ptr(443)}, // new, not in state
	}

	injectIDsFromState(entries, state)

	if entries[0].ID != nil {
		t.Errorf("new entry should have nil ID, got %v", *entries[0].ID)
	}
}

func TestInjectIDsFromState_NilState(t *testing.T) {
	entries := []apiServiceEntry{
		{Type: "http", Port: int64Ptr(80)},
	}

	// Should not panic
	injectIDsFromState(entries, nil)

	if entries[0].ID != nil {
		t.Errorf("nil state should leave ID as nil, got %v", *entries[0].ID)
	}
}

// ---------------------------------------------------------------------------
// Upstream server conversion
// ---------------------------------------------------------------------------

func TestUpstreamServersRoundTrip(t *testing.T) {
	models := []DomainUpstreamServerModel{
		{
			IP:        types.StringValue("10.0.0.1"),
			DNSRecord: types.StringNull(),
			Port:      types.Int64Value(8080),
			Weight:    types.Int64Value(50),
			Type:      types.StringValue("primary"),
			Name:      types.StringValue("web1"),
		},
		{
			IP:        types.StringNull(),
			DNSRecord: types.StringValue("web2.example.com"),
			Port:      types.Int64Value(8080),
			Weight:    types.Int64Value(50),
			Type:      types.StringValue("backup"),
			Name:      types.StringValue(""),
		},
	}

	api := upstreamServersToAPI(models)
	back := upstreamServersFromAPI(api)

	if len(back) != 2 {
		t.Fatalf("round-trip returned %d servers, want 2", len(back))
	}

	// First server: has IP, no DNS
	if back[0].IP.ValueString() != "10.0.0.1" {
		t.Errorf("server[0] IP = %q, want 10.0.0.1", back[0].IP.ValueString())
	}
	if !back[0].DNSRecord.IsNull() {
		t.Errorf("server[0] DNSRecord should be null, got %v", back[0].DNSRecord)
	}
	if back[0].Name.ValueString() != "web1" {
		t.Errorf("server[0] Name = %q, want web1", back[0].Name.ValueString())
	}

	// Second server: has DNS, no IP
	if !back[1].IP.IsNull() {
		t.Errorf("server[1] IP should be null, got %v", back[1].IP)
	}
	if back[1].DNSRecord.ValueString() != "web2.example.com" {
		t.Errorf("server[1] DNSRecord = %q, want web2.example.com", back[1].DNSRecord.ValueString())
	}
}

// ---------------------------------------------------------------------------
// apiToServicesModel dispatching
// ---------------------------------------------------------------------------

func TestApiToServicesModel_AllTypes(t *testing.T) {
	entries := []apiServiceEntry{
		{ID: int64Ptr(1), Type: "http", Port: int64Ptr(80), Upstream: rawMsg(apiHTTPUpstream{Balancer: "roundrobin", Upstreams: []apiUpstreamServer{}})},
		{ID: int64Ptr(2), Type: "nat", Port: int64Ptr(53), Proto: "udp", Upstream: rawMsg(apiNATUpstream{IP: "1.1.1.1", Port: 53})},
		{ID: int64Ptr(3), Type: "nat-all", Proto: "tcp", Upstream: rawMsg("2.2.2.2")},
		{ID: int64Ptr(4), Type: "tcpproxy", Port: int64Ptr(3306), Upstream: rawMsg(apiTCPProxyUpstream{Upstreams: []apiUpstreamServer{}})},
		{ID: int64Ptr(5), Type: "websocket", Port: int64Ptr(8443), Upstream: rawMsg(apiWebSocketUpstream{SSL: true, Upstreams: []apiUpstreamServer{}})},
	}

	m := &DomainServicesResourceModel{}
	apiToServicesModel(entries, m)

	if len(m.HTTP) != 1 {
		t.Errorf("HTTP count = %d, want 1", len(m.HTTP))
	}
	if len(m.NAT) != 1 {
		t.Errorf("NAT count = %d, want 1", len(m.NAT))
	}
	if len(m.NATAll) != 1 {
		t.Errorf("NATAll count = %d, want 1", len(m.NATAll))
	}
	if len(m.TCPProxy) != 1 {
		t.Errorf("TCPProxy count = %d, want 1", len(m.TCPProxy))
	}
	if len(m.WebSocket) != 1 {
		t.Errorf("WebSocket count = %d, want 1", len(m.WebSocket))
	}
}

func TestApiToServicesModel_UnknownTypeIgnored(t *testing.T) {
	entries := []apiServiceEntry{
		{ID: int64Ptr(1), Type: "futuristic-service"},
	}

	m := &DomainServicesResourceModel{}
	apiToServicesModel(entries, m)

	total := len(m.HTTP) + len(m.NAT) + len(m.NATAll) + len(m.TCPProxy) + len(m.WebSocket)
	if total != 0 {
		t.Errorf("unknown type should be ignored, but total entries = %d", total)
	}
}

// ---------------------------------------------------------------------------
// JSON round-trip: full service list through API format
// ---------------------------------------------------------------------------

func TestBuildServiceList_APIRoundTrip(t *testing.T) {
	original := &DomainServicesResourceModel{
		DomainID: types.Int64Value(42),
		HTTP: []DomainServiceHTTPModel{
			{
				Port:             types.Int64Value(443),
				SSL:              types.BoolValue(true),
				HTTP2:            types.BoolValue(true),
				DefaultDrop:      types.BoolNull(),
				UpstreamBalancer: types.StringValue("iphash"),
				UpstreamWeights:  types.BoolValue(false),
				UpstreamBackups:  types.BoolValue(false),
				UpstreamSSL:      types.BoolValue(true),
				Upstreams: []DomainUpstreamServerModel{
					{IP: types.StringValue("10.0.0.1"), DNSRecord: types.StringNull(), Port: types.Int64Value(8443), Weight: types.Int64Value(100), Type: types.StringValue("primary"), Name: types.StringValue("")},
				},
			},
		},
	}

	// model → API entries
	entries := buildServiceList(original)

	// Simulate API: marshal then unmarshal (as services_get would return)
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	var apiEntries []apiServiceEntry
	if err := json.Unmarshal(raw, &apiEntries); err != nil {
		t.Fatal(err)
	}

	// Inject IDs as API would
	for i := range apiEntries {
		id := int64(1000 + int64(i))
		apiEntries[i].ID = &id
	}

	// API → model
	result := &DomainServicesResourceModel{}
	apiToServicesModel(apiEntries, result)

	if len(result.HTTP) != 1 {
		t.Fatalf("expected 1 HTTP entry, got %d", len(result.HTTP))
	}

	h := result.HTTP[0]
	if h.Port.ValueInt64() != 443 {
		t.Errorf("Port = %d, want 443", h.Port.ValueInt64())
	}
	if h.UpstreamBalancer.ValueString() != "iphash" {
		t.Errorf("UpstreamBalancer = %q, want iphash", h.UpstreamBalancer.ValueString())
	}
	if h.ID.ValueInt64() != 1000 {
		t.Errorf("ID = %d, want 1000", h.ID.ValueInt64())
	}
}
