package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/qratorlabs/terraform-provider-qrator/internal/client"
	"golang.org/x/sync/errgroup"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type CDNResource struct {
	client *client.QratorClient
}

func NewCDNResource() resource.Resource {
	return &CDNResource{}
}

func (r *CDNResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cdn"
}

func (r *CDNResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a CDN configuration for a domain in Qrator.",
		Attributes: map[string]schema.Attribute{
			"domain_id": schema.Int64Attribute{
				Description: "The ID of the domain to configure CDN for.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"access_control_allow_origin": schema.ListAttribute{
				Description: "List of origins for the Access-Control-Allow-Origin header.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"cache_control": schema.BoolAttribute{
				Description: "Whether to enable cache control for the CDN.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"redirect_code": schema.Int64Attribute{
				Description: "HTTP redirect code (301, 302, 307, or 308).",
				Optional:    true,
				Validators: []validator.Int64{
					int64validator.OneOf(301, 302, 307, 308),
				},
			},
			"cache_ignore_params": schema.BoolAttribute{
				Description: "Whether to ignore query parameters when caching.",
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				Computed:    true,
			},
			"client_headers": schema.ListAttribute{
				Description: "List of headers to pass to the client.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"client_ip_header": schema.StringAttribute{
				Description: "Header name containing the client IP address.",
				Optional:    true,
				Computed:    true,
			},
			"upstream_headers": schema.ListAttribute{
				Description: "List of headers to pass to the upstream server.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"sni": schema.ListNestedAttribute{
				Description: "SNI configuration for CDN. List of hostname-to-certificate mappings.",
				Optional:    true,
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"host": schema.StringAttribute{
							Description: "The CDN hostname.",
							Required:    true,
						},
						"certificate": schema.Int64Attribute{
							Description: "The certificate ID from storage, or omit to use hostname without TLS.",
							Optional:    true,
						},
					},
				},
			},
		},
	}
	tflog.Debug(ctx, "Defined CDN resource schema")
}

func (r *CDNResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.QratorClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.QratorClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *CDNResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected numeric domain_id")
		return
	}
	resp.State.SetAttribute(ctx, path.Root("domain_id"), id)
}

func (r *CDNResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CDNModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.State.Set(ctx, &plan)
}

func (r *CDNResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (r *CDNResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CDNModel
	var state CDNModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := plan.DomainID.ValueInt64()
	apiPath := fmt.Sprintf("/request/cdn/%d", domainID)

	// access_control_allow_origin
	if !IsNullOrUnknown(plan.AccessControlAllowOrigin) &&
		ShouldUpdateList(plan.AccessControlAllowOrigin, state.AccessControlAllowOrigin, true) {
		var values []string
		plan.AccessControlAllowOrigin.ElementsAs(ctx, &values, false)
		if _, err := r.client.MakeRequest(ctx, apiPath, "access_control_allow_origin_set", values); err != nil {
			resp.Diagnostics.AddError("Failed to update access_control_allow_origin", err.Error())
			return
		}
	}

	// cache_control
	if !plan.CacheControl.IsNull() && !plan.CacheControl.IsUnknown() &&
		(state.CacheControl.IsNull() || plan.CacheControl.ValueBool() != state.CacheControl.ValueBool()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "cache_control_set", plan.CacheControl.ValueBool()); err != nil {
			resp.Diagnostics.AddError("Failed to update cache_control", err.Error())
			return
		}
	}

	// redirect_code
	if plan.RedirectCode.IsNull() {
		if !state.RedirectCode.IsNull() {
			if _, err := r.client.MakeRequest(ctx, apiPath, "redirect_set", nil); err != nil {
				resp.Diagnostics.AddError("Failed to disable redirect", err.Error())
				return
			}
		}
	} else if !plan.RedirectCode.IsUnknown() {
		if state.RedirectCode.IsNull() || plan.RedirectCode.ValueInt64() != state.RedirectCode.ValueInt64() {
			if _, err := r.client.MakeRequest(ctx, apiPath, "redirect_set", plan.RedirectCode.ValueInt64()); err != nil {
				resp.Diagnostics.AddError("Failed to update redirect_code", err.Error())
				return
			}
		}
	}

	// cache_ignore_params
	if !plan.CacheIgnoreParams.IsNull() && !plan.CacheIgnoreParams.IsUnknown() &&
		(state.CacheIgnoreParams.IsNull() || plan.CacheIgnoreParams.ValueBool() != state.CacheIgnoreParams.ValueBool()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "cache_ignore_params_set", plan.CacheIgnoreParams.ValueBool()); err != nil {
			resp.Diagnostics.AddError("Failed to update cache_ignore_params", err.Error())
			return
		}
	}

	// client_headers
	if !IsNullOrUnknown(plan.ClientHeaders) &&
		ShouldUpdateList(plan.ClientHeaders, state.ClientHeaders, true) {
		var values []string
		plan.ClientHeaders.ElementsAs(ctx, &values, false)
		if _, err := r.client.MakeRequest(ctx, apiPath, "client_headers_set", values); err != nil {
			resp.Diagnostics.AddError("Failed to update client_headers", err.Error())
			return
		}
	}

	// client_ip_header
	if !plan.ClientIPHeader.IsNull() && !plan.ClientIPHeader.IsUnknown() &&
		(state.ClientIPHeader.IsNull() || plan.ClientIPHeader.ValueString() != state.ClientIPHeader.ValueString()) {
		if _, err := r.client.MakeRequest(ctx, apiPath, "client_ip_header_set", plan.ClientIPHeader.ValueString()); err != nil {
			resp.Diagnostics.AddError("Failed to update client_ip_header", err.Error())
			return
		}
	}

	// upstream_headers
	if !IsNullOrUnknown(plan.UpstreamHeaders) &&
		ShouldUpdateList(plan.UpstreamHeaders, state.UpstreamHeaders, true) {
		var values []string
		plan.UpstreamHeaders.ElementsAs(ctx, &values, false)
		if _, err := r.client.MakeRequest(ctx, apiPath, "upstream_headers_set", values); err != nil {
			resp.Diagnostics.AddError("Failed to update upstream_headers", err.Error())
			return
		}
	}

	// sni
	if !plan.SNI.IsNull() && !plan.SNI.IsUnknown() {
		if err := r.updateSNI(ctx, apiPath, plan.SNI, state.SNI, &resp.Diagnostics); err != nil {
			return
		}
	}

	resp.State.Set(ctx, &plan)
}

func (r *CDNResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CDNModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := state.DomainID.ValueInt64()
	apiPath := fmt.Sprintf("/request/cdn/%d", domainID)

	var (
		accessControlAllowOrigin []string
		cacheControl             bool
		redirectCode             *int64
		cacheIgnoreParams        bool
		clientHeaders            []string
		clientIPHeader           *string
		upstreamHeaders          []string
		sniEntries               []cdnSNIEntry
	)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "access_control_allow_origin_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &accessControlAllowOrigin)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "cache_control_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &cacheControl)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "cache_ignore_params_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &cacheIgnoreParams)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "redirect_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &redirectCode)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "client_headers_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &clientHeaders)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "client_ip_header_get", nil)
		if err != nil {
			return err
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return err
		}
		clientIPHeader = &s
		return nil
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "upstream_headers_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &upstreamHeaders)
	})

	g.Go(func() error {
		v, err := r.client.MakeRequest(gctx, apiPath, "sni_get", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(v, &sniEntries)
	})

	if err := g.Wait(); err != nil {
		resp.Diagnostics.AddError("Failed to read CDN settings", err.Error())
		return
	}

	state.AccessControlAllowOrigin, _ = types.ListValueFrom(ctx, types.StringType, accessControlAllowOrigin)
	state.CacheControl = types.BoolValue(cacheControl)
	if redirectCode == nil {
		state.RedirectCode = types.Int64Null()
	} else {
		state.RedirectCode = types.Int64Value(*redirectCode)
	}
	state.CacheIgnoreParams = types.BoolValue(cacheIgnoreParams)
	state.ClientHeaders, _ = types.ListValueFrom(ctx, types.StringType, clientHeaders)
	if clientIPHeader == nil {
		state.ClientIPHeader = types.StringNull()
	} else {
		state.ClientIPHeader = types.StringValue(*clientIPHeader)
	}
	state.UpstreamHeaders, _ = types.ListValueFrom(ctx, types.StringType, upstreamHeaders)

	state.AccessControlAllowOrigin, _ = NormalizeStringList(ctx, state.AccessControlAllowOrigin)
	state.ClientHeaders, _ = NormalizeStringList(ctx, state.ClientHeaders)
	state.UpstreamHeaders, _ = NormalizeStringList(ctx, state.UpstreamHeaders)

	state.SNI = sniEntriesToList(ctx, sniEntries, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.State.Set(ctx, &state)
}

// cdnSNIEntry represents the API structure for a CDN SNI entry.
type cdnSNIEntry struct {
	Host        string `json:"host"`
	Certificate *int64 `json:"certificate"`
}

// updateSNI calls sni_set if the SNI configuration has changed.
func (r *CDNResource) updateSNI(ctx context.Context, apiPath string, plan, state types.List, diags *diag.Diagnostics) error {
	var planEntries, stateEntries []CDNSNIEntryModel

	d := plan.ElementsAs(ctx, &planEntries, false)
	diags.Append(d...)
	if diags.HasError() {
		return fmt.Errorf("failed to parse plan SNI")
	}

	if !state.IsNull() && !state.IsUnknown() {
		d = state.ElementsAs(ctx, &stateEntries, false)
		diags.Append(d...)
		if diags.HasError() {
			return fmt.Errorf("failed to parse state SNI")
		}
	}

	// Check if changed
	if sniEntriesEqual(planEntries, stateEntries) {
		return nil
	}

	params := make([]map[string]interface{}, len(planEntries))
	for i, e := range planEntries {
		entry := map[string]interface{}{
			"host": e.Host.ValueString(),
		}
		if e.Certificate.IsNull() {
			entry["certificate"] = nil
		} else {
			entry["certificate"] = e.Certificate.ValueInt64()
		}
		params[i] = entry
	}

	if _, err := r.client.MakeRequest(ctx, apiPath, "sni_set", params); err != nil {
		diags.AddError("Failed to update sni", err.Error())
		return err
	}

	return nil
}

// sniEntriesEqual compares two slices of CDNSNIEntryModel for equality.
func sniEntriesEqual(a, b []CDNSNIEntryModel) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Host.ValueString() != b[i].Host.ValueString() {
			return false
		}
		if a[i].Certificate.IsNull() != b[i].Certificate.IsNull() {
			return false
		}
		if !a[i].Certificate.IsNull() && a[i].Certificate.ValueInt64() != b[i].Certificate.ValueInt64() {
			return false
		}
	}
	return true
}

// sniEntriesToList converts API SNI entries to a Terraform List value.
func sniEntriesToList(ctx context.Context, entries []cdnSNIEntry, diags *diag.Diagnostics) types.List {
	models := make([]CDNSNIEntryModel, len(entries))
	for i, e := range entries {
		models[i] = CDNSNIEntryModel{
			Host: types.StringValue(e.Host),
		}
		if e.Certificate != nil {
			models[i].Certificate = types.Int64Value(*e.Certificate)
		} else {
			models[i].Certificate = types.Int64Null()
		}
	}

	sniAttrTypes := map[string]attr.Type{
		"host":        types.StringType,
		"certificate": types.Int64Type,
	}

	elems := make([]attr.Value, len(models))
	for i, m := range models {
		obj, d := types.ObjectValueFrom(ctx, sniAttrTypes, m)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: sniAttrTypes})
		}
		elems[i] = obj
	}

	list, d := types.ListValue(types.ObjectType{AttrTypes: sniAttrTypes}, elems)
	diags.Append(d...)
	return list
}
