package provider

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// apiContentCompression is the payload of content_compression_get/set
// (CdnContentCompression). All keys are required by the API.
type apiContentCompression struct {
	Gzip    []string `json:"gzip"`
	Br      []string `json:"br"`
	Deflate []string `json:"deflate"`
	Zstd    []string `json:"zstd"`
}

// CDNContentCompressionModel is the model for the content_compression attribute.
type CDNContentCompressionModel struct {
	Gzip    types.Set `tfsdk:"gzip"`
	Br      types.Set `tfsdk:"br"`
	Deflate types.Set `tfsdk:"deflate"`
	Zstd    types.Set `tfsdk:"zstd"`
}

var contentCompressionAttrTypes = map[string]attr.Type{
	"gzip":    types.SetType{ElemType: types.StringType},
	"br":      types.SetType{ElemType: types.StringType},
	"deflate": types.SetType{ElemType: types.StringType},
	"zstd":    types.SetType{ElemType: types.StringType},
}

// mimeTypeRE accepts "*" or a "type/subtype" MIME type made of RFC 7230 token
// characters. Anything finer (wildcards, case) is left to the API.
var mimeTypeRE = regexp.MustCompile("^(\\*|[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+)$")

func compressionAlgorithmAttr(algorithm string) schema.SetAttribute {
	return schema.SetAttribute{
		Description: "MIME types compressed with " + algorithm + ". `[\"*\"]` — any MIME type, `[]` — " + algorithm + " is disabled.",
		Required:    true,
		ElementType: types.StringType,
		Validators: []validator.Set{
			setvalidator.ValueStringsAre(
				stringvalidator.RegexMatches(mimeTypeRE, `must be "*" or a MIME type such as "text/html"`),
			),
		},
	}
}

// contentCompressionSchemaAttribute returns the schema of qrator_cdn.content_compression.
func contentCompressionSchemaAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Description: "MIME types that CDN compresses with each algorithm. All algorithms must be listed; " +
			"the Qrator default is `[\"*\"]` for each of them. When omitted, the setting is not managed by Terraform; " +
			"removing the attribute stops managing it and leaves it unchanged in Qrator. Replaces `compress_disabled`.",
		// Not Computed for the same reason as access_filter: an unset
		// Optional+Computed object would produce a perpetual in-place update.
		Optional: true,
		Attributes: map[string]schema.Attribute{
			"gzip":    compressionAlgorithmAttr("gzip"),
			"br":      compressionAlgorithmAttr("br"),
			"deflate": compressionAlgorithmAttr("deflate"),
			"zstd":    compressionAlgorithmAttr("zstd"),
		},
	}
}

// contentCompressionToAPI converts a known content_compression object to the
// content_compression_set payload. Lists are never null: the API requires all keys.
func contentCompressionToAPI(ctx context.Context, obj types.Object, diags *diag.Diagnostics) (apiContentCompression, bool) {
	var m CDNContentCompressionModel
	diags.Append(obj.As(ctx, &m, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return apiContentCompression{}, false
	}
	out := apiContentCompression{
		Gzip:    setStrings(ctx, m.Gzip, diags),
		Br:      setStrings(ctx, m.Br, diags),
		Deflate: setStrings(ctx, m.Deflate, diags),
		Zstd:    setStrings(ctx, m.Zstd, diags),
	}
	return out, !diags.HasError()
}

// contentCompressionFromAPI converts a content_compression_get result to the
// attribute value. A missing key is treated as an empty list.
func contentCompressionFromAPI(ctx context.Context, api apiContentCompression, diags *diag.Diagnostics) types.Object {
	toSet := func(values []string) types.Set {
		if values == nil {
			values = []string{}
		}
		s, d := types.SetValueFrom(ctx, types.StringType, values)
		diags.Append(d...)
		return s
	}
	obj, d := types.ObjectValueFrom(ctx, contentCompressionAttrTypes, CDNContentCompressionModel{
		Gzip:    toSet(api.Gzip),
		Br:      toSet(api.Br),
		Deflate: toSet(api.Deflate),
		Zstd:    toSet(api.Zstd),
	})
	diags.Append(d...)
	return obj
}
