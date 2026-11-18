package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestDomainRedirectsValidateConfigUnknownList(t *testing.T) {
	ctx := context.Background()
	r := &DomainRedirectsResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	objectType := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	listType := objectType.AttributeTypes["redirects"]
	for _, tc := range []struct {
		name  string
		value tftypes.Value
	}{
		{"unknown", tftypes.NewValue(listType, tftypes.UnknownValue)},
		{"empty", tftypes.NewValue(listType, []tftypes.Value{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := tftypes.NewValue(objectType, map[string]tftypes.Value{
				"domain_id": tftypes.NewValue(tftypes.Number, 1),
				"redirects": tc.value,
			})
			req := resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: raw}}
			var resp resource.ValidateConfigResponse
			r.ValidateConfig(ctx, req, &resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected validation diagnostics: %v", resp.Diagnostics)
			}
		})
	}
}
