package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

var _ provider.Provider = &QratorProvider{}

type QratorProvider struct {
	version string
}

type qratorProviderConfig struct {
	APIKey   types.String `tfsdk:"api_key"`
	Endpoint types.String `tfsdk:"endpoint"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &QratorProvider{version: version}
	}
}

func (p *QratorProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "qrator"
	resp.Version = p.version
	tflog.Debug(ctx, "Set provider metadata", map[string]interface{}{
		"type_name": resp.TypeName,
		"version":   resp.Version,
	})
}

func (p *QratorProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"api_key": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "The API key for authenticating requests to the Qrator API. Can also be set via the QRATOR_API_KEY environment variable.",
			},
			"endpoint": schema.StringAttribute{
				Required:    true,
				Description: "The base URL of the Qrator API (e.g., 'https://api.qrator.net'). Can also be set via the QRATOR_ENDPOINT environment variable.",
			},
		},
	}
}

func (p *QratorProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config qratorProviderConfig
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiKey := config.APIKey.ValueString()
	if apiKey == "" {
		apiKey = os.Getenv("QRATOR_API_KEY")
	}
	endpoint := config.Endpoint.ValueString()
	if endpoint == "" {
		endpoint = os.Getenv("QRATOR_ENDPOINT")
	}

	if apiKey == "" {
		resp.Diagnostics.AddError("Missing API Key", "The 'api_key' attribute or QRATOR_API_KEY environment variable must be set.")
	}
	if endpoint == "" {
		resp.Diagnostics.AddError("Missing Endpoint", "The 'endpoint' attribute or QRATOR_ENDPOINT environment variable must be set.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	debug := os.Getenv("QRATOR_DEBUG") == "true"
	c := client.NewQratorClient(apiKey, endpoint, debug)

	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *QratorProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return nil
}

func (p *QratorProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCDNResource,
		NewClientCertificateResource,
	}
}
