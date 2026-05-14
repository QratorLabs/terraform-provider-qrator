package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
)

var _ datasource.DataSource = &CDNIPsDataSource{}
var _ datasource.DataSourceWithConfigure = &CDNIPsDataSource{}

type CDNIPsDataSource struct {
	client client.QratorClientAPI
}

type CDNIPsModel struct {
	DomainID types.Int64  `tfsdk:"domain_id"`
	Region   types.String `tfsdk:"region"`
	IPs      types.List   `tfsdk:"ips"`
}

func NewCDNIPsDataSource() datasource.DataSource {
	return &CDNIPsDataSource{}
}

func (d *CDNIPsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cdn_ips"
}

func (d *CDNIPsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Returns the list of IP addresses of CDN caching servers for a given CDN domain.",
		Attributes: map[string]schema.Attribute{
			"domain_id": schema.Int64Attribute{
				Required:    true,
				Description: "The ID of the CDN domain.",
			},
			"region": schema.StringAttribute{
				Optional:    true,
				Description: `CDN region to query: "ru", "global", or omit for the default region.`,
				Validators: []validator.String{
					stringvalidator.OneOf("ru", "global"),
				},
			},
			"ips": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "List of IP addresses of CDN caching servers.",
			},
		},
	}
}

func (d *CDNIPsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.QratorClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type",
			fmt.Sprintf("Expected *client.QratorClient, got %T", req.ProviderData))
		return
	}
	d.client = c
}

func (d *CDNIPsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data CDNIPsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := fmt.Sprintf("/request/cdn/%d", data.DomainID.ValueInt64())

	var params interface{}
	if !data.Region.IsNull() && !data.Region.IsUnknown() {
		params = data.Region.ValueString()
	}

	raw, err := d.client.MakeRequest(ctx, apiPath, "cdn_ips_get", params)
	if err != nil {
		resp.Diagnostics.AddError("Failed to fetch CDN IPs", err.Error())
		return
	}

	var ips []string
	if err := json.Unmarshal(raw, &ips); err != nil {
		resp.Diagnostics.AddError("Failed to parse CDN IPs response", err.Error())
		return
	}

	list, diags := types.ListValueFrom(ctx, types.StringType, ips)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.IPs = list

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
