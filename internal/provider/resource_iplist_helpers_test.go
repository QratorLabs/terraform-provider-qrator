package provider

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestParseAPITuples(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		wantFirst *IPListEntryModel
		wantErr   bool
	}{
		{
			name:      "full tuple (ip, ttl, comment)",
			input:     `[["1.2.3.4", 3600, "test"]]`,
			wantCount: 1,
			wantFirst: &IPListEntryModel{
				IP:      types.StringValue("1.2.3.4"),
				TTL:     types.Int64Value(3600),
				Comment: types.StringValue("test"),
			},
		},
		{
			name:      "ip only",
			input:     `[["1.2.3.4"]]`,
			wantCount: 1,
			wantFirst: &IPListEntryModel{
				IP:      types.StringValue("1.2.3.4"),
				TTL:     types.Int64Value(0),
				Comment: types.StringValue(""),
			},
		},
		{
			name:      "ip and ttl",
			input:     `[["1.2.3.4", 7200]]`,
			wantCount: 1,
			wantFirst: &IPListEntryModel{
				IP:      types.StringValue("1.2.3.4"),
				TTL:     types.Int64Value(7200),
				Comment: types.StringValue(""),
			},
		},
		{
			name:      "empty list",
			input:     `[]`,
			wantCount: 0,
		},
		{
			name:      "multiple entries",
			input:     `[["1.1.1.1", 0, "a"], ["2.2.2.2", 60, "b"]]`,
			wantCount: 2,
			wantFirst: &IPListEntryModel{
				IP:      types.StringValue("1.1.1.1"),
				TTL:     types.Int64Value(0),
				Comment: types.StringValue("a"),
			},
		},
		{
			name:    "invalid json",
			input:   `not json`,
			wantErr: true,
		},
		{
			name:      "empty sub-tuple skipped",
			input:     `[[]]`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAPITuples(json.RawMessage(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAPITuples() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != tt.wantCount {
				t.Fatalf("parseAPITuples() returned %d entries, want %d", len(got), tt.wantCount)
			}
			if tt.wantFirst != nil && len(got) > 0 {
				e := got[0]
				if e.IP.ValueString() != tt.wantFirst.IP.ValueString() {
					t.Errorf("IP = %q, want %q", e.IP.ValueString(), tt.wantFirst.IP.ValueString())
				}
				if e.TTL.ValueInt64() != tt.wantFirst.TTL.ValueInt64() {
					t.Errorf("TTL = %d, want %d", e.TTL.ValueInt64(), tt.wantFirst.TTL.ValueInt64())
				}
				if e.Comment.ValueString() != tt.wantFirst.Comment.ValueString() {
					t.Errorf("Comment = %q, want %q", e.Comment.ValueString(), tt.wantFirst.Comment.ValueString())
				}
			}
		})
	}
}

func TestEntriesToAPITuples(t *testing.T) {
	entries := []IPListEntryModel{
		{IP: types.StringValue("1.2.3.4"), TTL: types.Int64Value(3600), Comment: types.StringValue("test")},
		{IP: types.StringValue("5.6.7.8"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
	}

	tuples := entriesToAPITuples(entries)

	if len(tuples) != 2 {
		t.Fatalf("got %d tuples, want 2", len(tuples))
	}

	// First tuple
	if tuples[0][0] != "1.2.3.4" {
		t.Errorf("tuples[0][0] = %v, want 1.2.3.4", tuples[0][0])
	}
	if tuples[0][1] != int64(3600) {
		t.Errorf("tuples[0][1] = %v, want 3600", tuples[0][1])
	}
	if tuples[0][2] != "test" {
		t.Errorf("tuples[0][2] = %v, want test", tuples[0][2])
	}
}

func TestEntriesToAPITuples_RoundTrip(t *testing.T) {
	entries := []IPListEntryModel{
		{IP: types.StringValue("10.0.0.1"), TTL: types.Int64Value(60), Comment: types.StringValue("server")},
	}

	tuples := entriesToAPITuples(entries)
	raw, err := json.Marshal(tuples)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := parseAPITuples(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}

	if len(parsed) != 1 {
		t.Fatalf("round-trip returned %d entries, want 1", len(parsed))
	}

	if parsed[0].IP.ValueString() != "10.0.0.1" {
		t.Errorf("IP = %q, want 10.0.0.1", parsed[0].IP.ValueString())
	}
	if parsed[0].TTL.ValueInt64() != 60 {
		t.Errorf("TTL = %d, want 60", parsed[0].TTL.ValueInt64())
	}
	if parsed[0].Comment.ValueString() != "server" {
		t.Errorf("Comment = %q, want server", parsed[0].Comment.ValueString())
	}
}

func TestIpEntryEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b IPListEntryModel
		want bool
	}{
		{
			"all same",
			IPListEntryModel{IP: types.StringValue("1.1.1.1"), TTL: types.Int64Value(0), Comment: types.StringValue("x")},
			IPListEntryModel{IP: types.StringValue("1.1.1.1"), TTL: types.Int64Value(0), Comment: types.StringValue("x")},
			true,
		},
		{
			"different ip",
			IPListEntryModel{IP: types.StringValue("1.1.1.1"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
			IPListEntryModel{IP: types.StringValue("2.2.2.2"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
			false,
		},
		{
			"different ttl",
			IPListEntryModel{IP: types.StringValue("1.1.1.1"), TTL: types.Int64Value(0), Comment: types.StringValue("")},
			IPListEntryModel{IP: types.StringValue("1.1.1.1"), TTL: types.Int64Value(60), Comment: types.StringValue("")},
			false,
		},
		{
			"different comment",
			IPListEntryModel{IP: types.StringValue("1.1.1.1"), TTL: types.Int64Value(0), Comment: types.StringValue("a")},
			IPListEntryModel{IP: types.StringValue("1.1.1.1"), TTL: types.Int64Value(0), Comment: types.StringValue("b")},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipEntryEqual(&tt.a, &tt.b)
			if got != tt.want {
				t.Errorf("ipEntryEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}
