package provider

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestContentCompressionDisabledAlgos(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"all enabled via star", `{"gzip":["*"],"br":["*"],"deflate":["*"],"zstd":["*"]}`, []string{}},
		{"all enabled via mimes", `{"gzip":["text/html"],"br":["text/html"],"deflate":["application/json"],"zstd":["text/css"]}`, []string{}},
		{"all disabled", `{"gzip":[],"br":[],"deflate":[],"zstd":[]}`, []string{"gzip", "deflate", "br", "zstd"}},
		{"only gzip disabled", `{"gzip":[],"br":["*"],"deflate":["*"],"zstd":["*"]}`, []string{"gzip"}},
		{"gzip and zstd disabled keep api order", `{"gzip":[],"br":["*"],"deflate":["*"],"zstd":[]}`, []string{"gzip", "zstd"}},
		{"missing keys count as disabled", `{"gzip":["*"]}`, []string{"deflate", "br", "zstd"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cc apiContentCompression
			if err := json.Unmarshal([]byte(tt.input), &cc); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got := cc.disabledAlgos()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("disabledAlgos() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContentCompressionFromDisabled(t *testing.T) {
	tests := []struct {
		name     string
		disabled []string
		want     apiContentCompression
	}{
		{
			name:     "none disabled -> all star",
			disabled: nil,
			want:     apiContentCompression{Gzip: []string{"*"}, Deflate: []string{"*"}, Br: []string{"*"}, Zstd: []string{"*"}},
		},
		{
			name:     "gzip disabled",
			disabled: []string{"gzip"},
			want:     apiContentCompression{Gzip: []string{}, Deflate: []string{"*"}, Br: []string{"*"}, Zstd: []string{"*"}},
		},
		{
			name:     "case and spaces are normalized",
			disabled: []string{"  GZIP ", "Br"},
			want:     apiContentCompression{Gzip: []string{}, Deflate: []string{"*"}, Br: []string{}, Zstd: []string{"*"}},
		},
		{
			name:     "all disabled",
			disabled: []string{"gzip", "deflate", "br", "zstd"},
			want:     apiContentCompression{Gzip: []string{}, Deflate: []string{}, Br: []string{}, Zstd: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contentCompressionFromDisabled(tt.disabled)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("contentCompressionFromDisabled() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestContentCompressionRoundTrip verifies that a compress_disabled list survives a
// set -> get round trip through the CdnContentCompression representation, normalized
// to cdnCompressAlgos order.
func TestContentCompressionRoundTrip(t *testing.T) {
	for _, disabled := range [][]string{
		{},
		{"gzip"},
		{"zstd", "gzip"},
		{"gzip", "deflate", "br", "zstd"},
	} {
		want := make([]string, 0, len(cdnCompressAlgos))
		set := map[string]bool{}
		for _, a := range disabled {
			set[a] = true
		}
		for _, a := range cdnCompressAlgos {
			if set[a] {
				want = append(want, a)
			}
		}

		got := contentCompressionFromDisabled(disabled).disabledAlgos()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round trip for %v: got %v, want %v", disabled, got, want)
		}
	}
}
