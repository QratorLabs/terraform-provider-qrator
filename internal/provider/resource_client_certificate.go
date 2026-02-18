package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/qratorlabs/terraform-provider-qrator/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	CertTypeUpload      = "upload"
	CertTypeLetsEncrypt = "letsencrypt"
)

type ClientCertificateResource struct {
	client *client.QratorClient
}

type retryConfig struct {
	UploadInitialDelay      time.Duration
	UploadRetryDelay        time.Duration
	UploadMaxRetries        int
	LetsEncryptInitialDelay time.Duration
	LetsEncryptRetryDelay   time.Duration
	LetsEncryptMaxRetries   int
}

var defaultRetryConfig = retryConfig{
	UploadInitialDelay:      10 * time.Second,
	UploadRetryDelay:        5 * time.Second,
	UploadMaxRetries:        3,
	LetsEncryptInitialDelay: 5 * time.Minute,
	LetsEncryptRetryDelay:   1 * time.Minute,
	LetsEncryptMaxRetries:   20,
}

type ClientCertificateResourceModel struct {
	ID             types.Int64  `tfsdk:"id"`
	ClientID       types.Int64  `tfsdk:"client_id"`
	Type           types.String `tfsdk:"type"`
	NotValidBefore types.Int64  `tfsdk:"not_valid_before"`
	NotValidAfter  types.Int64  `tfsdk:"not_valid_after"`
	Autoupdate     types.String `tfsdk:"autoupdate"`
	DomainID       types.Int64  `tfsdk:"domain_id"`
	Hostnames      types.List   `tfsdk:"hostnames"`
	ProtectKey     types.Bool   `tfsdk:"protect_key"`
	Certificates   types.List   `tfsdk:"certificates"`
	Links          types.List   `tfsdk:"links"`
}

type CertDetailModel struct {
	Type types.String `tfsdk:"type"`
	Cert types.String `tfsdk:"cert"`
	Key  types.String `tfsdk:"key"`
}

type CertLinkModel struct {
	LinkID      types.Int64  `tfsdk:"link_id"`
	Port        types.Int64  `tfsdk:"port"`
	Hostname    types.String `tfsdk:"hostname"`
	DomainID    types.Int64  `tfsdk:"domain_id"`
	Certificate types.Int64  `tfsdk:"certificate"`
}

type certificateDetails struct {
	ID             int64         `json:"id"`
	Type           string        `json:"type"`
	NotValidBefore int64         `json:"not_valid_before"`
	NotValidAfter  int64         `json:"not_valid_after"`
	Autoupdate     interface{}   `json:"autoupdate"`
	DomainID       *int64        `json:"domain_id"`
	Hostnames      []string      `json:"hostnames"`
	ProtectKey     bool          `json:"protect_key"`
	Certificates   []certDetails `json:"certificates"`
	Links          []linkDetails `json:"links"`
}

type certDetails struct {
	Type string `json:"type"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type linkDetails struct {
	LinkID      int64   `json:"link_id"`
	Port        int64   `json:"port"`
	Hostname    *string `json:"hostname"`
	DomainID    int64   `json:"domain_id"`
	Certificate int64   `json:"certificate"`
}

type requestDetails struct {
	ID     int64 `json:"id"`
	Result struct {
		Chains []struct {
			ChainKey string `json:"chain_key"`
			ChainID  int64  `json:"chain_id"`
		} `json:"chains"`
	} `json:"result"`
}

func NewClientCertificateResource() resource.Resource {
	return &ClientCertificateResource{}
}

func (r *ClientCertificateResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_client_certificate"
}

func (r *ClientCertificateResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages client certificates in Qrator. Supports 'upload' and 'letsencrypt' certificate types.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "The unique identifier of the certificate.",
				Computed:    true,
			},
			"client_id": schema.Int64Attribute{
				Description: "The ID of the client owning the certificate.",
				Required:    true,
			},
			"type": schema.StringAttribute{
				Description: "The type of certificate. Must be either 'upload' or 'letsencrypt'.",
				Required:    true,
			},
			"not_valid_before": schema.Int64Attribute{
				Description: "The timestamp (Unix) when the certificate becomes valid.",
				Computed:    true,
			},
			"not_valid_after": schema.Int64Attribute{
				Description: "The timestamp (Unix) when the certificate expires.",
				Computed:    true,
			},
			"autoupdate": schema.StringAttribute{
				Description: "The autoupdate setting for the certificate.",
				Computed:    true,
				Optional:    true,
			},
			"domain_id": schema.Int64Attribute{
				Description: "The ID of the domain associated with the certificate.",
				Computed:    true,
				Optional:    true,
			},
			"hostnames": schema.ListAttribute{
				Description: "The list of hostnames covered by the certificate.",
				ElementType: types.StringType,
				Computed:    true,
				Optional:    true,
			},
			"protect_key": schema.BoolAttribute{
				Description: "Indicates whether the private key is protected.",
				Computed:    true,
			},
			"certificates": schema.ListNestedAttribute{
				Description: "The certificate details, including type, content, and private key.",
				Computed:    true,
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							Description: "The certificate algorithm type (e.g., 'rsa', 'ecc').",
							Computed:    true,
							Optional:    true,
						},
						"cert": schema.StringAttribute{
							Description: "The certificate content (PEM format).",
							Computed:    true,
							Optional:    true,
							Sensitive:   true,
						},
						"key": schema.StringAttribute{
							Description: "The private key content (PEM format).",
							Computed:    true,
							Optional:    true,
							Sensitive:   true,
						},
					},
				},
			},
			"links": schema.ListNestedAttribute{
				Description: "The list of SNI links using this certificate.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"link_id": schema.Int64Attribute{
							Computed: true,
						},
						"port": schema.Int64Attribute{
							Computed: true,
						},
						"hostname": schema.StringAttribute{
							Computed: true,
							Optional: true,
						},
						"domain_id": schema.Int64Attribute{
							Computed: true,
						},
						"certificate": schema.Int64Attribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (r *ClientCertificateResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ClientCertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ClientCertificateResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.validatePlan(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Validation Error", err.Error())
		return
	}

	var originalCerts []CertDetailModel
	if !plan.Certificates.IsNull() {
		d := plan.Certificates.ElementsAs(ctx, &originalCerts, false)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	path := fmt.Sprintf("/request/client/%d", plan.ClientID.ValueInt64())

	switch plan.Type.ValueString() {
	case CertTypeUpload:
		r.handleUploadCertificate(ctx, path, &plan, &resp.Diagnostics)
	case CertTypeLetsEncrypt:
		r.handleLetsEncryptCertificate(ctx, path, &plan, &resp.Diagnostics)
	default:
		resp.Diagnostics.AddError("Validation Error", fmt.Sprintf("Unknown certificate type: %s", plan.Type.ValueString()))
		return
	}

	if resp.Diagnostics.HasError() {
		return
	}

	if len(originalCerts) > 0 {
		plan.Certificates = restoreSensitiveCertificates(ctx, originalCerts, plan.Certificates, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *ClientCertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ClientCertificateResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := fmt.Sprintf("/request/client/%d", state.ClientID.ValueInt64())
	cert, err := r.getCertificateDetails(ctx, path, state.ID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("API Error", fmt.Sprintf("Failed to read certificate (ID: %d): %v", state.ID.ValueInt64(), err))
		return
	}

	var existingCerts []CertDetailModel
	if !state.Certificates.IsNull() {
		d := state.Certificates.ElementsAs(ctx, &existingCerts, false)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	r.mapCertificateToModel(ctx, cert, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(existingCerts) > 0 {
		state.Certificates = restoreSensitiveCertificates(ctx, existingCerts, state.Certificates, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ClientCertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"Client certificates cannot be updated via the Qrator API. Please delete and recreate the certificate.",
	)
}

func (r *ClientCertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ClientCertificateResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	path := fmt.Sprintf("/request/client/%d", state.ClientID.ValueInt64())
	_, err := r.client.MakeRequest(ctx, path, "certificate_remove", []int64{state.ID.ValueInt64()})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Certificate",
			fmt.Sprintf("Failed to delete certificate (ID: %d): %v", state.ID.ValueInt64(), err),
		)
		return
	}
}

func (r *ClientCertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Format: "client_id/certificate_id"
	parts := strings.SplitN(req.ID, "/", 2)
	if len(parts) != 2 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected format: client_id/certificate_id, got: %s", req.ID),
		)
		return
	}

	clientID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", fmt.Sprintf("client_id must be numeric: %v", err))
		return
	}
	certID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", fmt.Sprintf("certificate_id must be numeric: %v", err))
		return
	}

	path := fmt.Sprintf("/request/client/%d", clientID)
	cert, err := r.getCertificateDetails(ctx, path, certID)
	if err != nil {
		resp.Diagnostics.AddError("API Error", fmt.Sprintf("Failed to read certificate: %v", err))
		return
	}

	var state ClientCertificateResourceModel
	state.ClientID = types.Int64Value(clientID)
	r.mapCertificateToModel(ctx, cert, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ClientCertificateResource) validatePlan(ctx context.Context, plan *ClientCertificateResourceModel) error {
	if plan.ClientID.IsNull() || plan.ClientID.ValueInt64() <= 0 {
		return fmt.Errorf("client_id must be a positive integer")
	}

	certType := plan.Type.ValueString()
	if certType != CertTypeUpload && certType != CertTypeLetsEncrypt {
		return fmt.Errorf("type must be either 'upload' or 'letsencrypt', got: %s", certType)
	}

	if certType == CertTypeUpload {
		var certDetails []CertDetailModel
		if plan.Certificates.IsNull() {
			return fmt.Errorf("certificates must be provided for 'upload' type")
		}
		if d := plan.Certificates.ElementsAs(ctx, &certDetails, false); d.HasError() {
			return fmt.Errorf("failed to parse certificates: %v", d)
		}
		if len(certDetails) == 0 {
			return fmt.Errorf("at least one certificate must be provided for 'upload' type")
		}
		for i, cert := range certDetails {
			if cert.Cert.IsNull() || cert.Cert.ValueString() == "" {
				return fmt.Errorf("certificate %d: cert must not be empty", i)
			}
			if cert.Key.IsNull() || cert.Key.ValueString() == "" {
				return fmt.Errorf("certificate %d: key must not be empty", i)
			}
		}
	}

	if certType == CertTypeLetsEncrypt {
		var hostnames []string
		if plan.Hostnames.IsNull() {
			return fmt.Errorf("hostnames must be provided for 'letsencrypt' type")
		}
		if d := plan.Hostnames.ElementsAs(ctx, &hostnames, false); d.HasError() {
			return fmt.Errorf("failed to parse hostnames: %v", d)
		}
		if len(hostnames) == 0 {
			return fmt.Errorf("at least one hostname must be provided for 'letsencrypt' type")
		}
	}

	return nil
}

func (r *ClientCertificateResource) handleUploadCertificate(ctx context.Context, path string, plan *ClientCertificateResourceModel, diags *diag.Diagnostics) {
	var certDetails []CertDetailModel
	d := plan.Certificates.ElementsAs(ctx, &certDetails, false)
	diags.Append(d...)
	if diags.HasError() {
		return
	}

	tflog.Debug(ctx, "Preparing certificate upload", map[string]interface{}{
		"client_id": plan.ClientID.ValueInt64(),
		"cert_type": certDetails[0].Type.ValueString(),
	})

	params := []string{
		certDetails[0].Cert.ValueString(),
		certDetails[0].Key.ValueString(),
	}
	result, err := r.client.MakeRequest(ctx, path, "certrequest_upload", params)
	if err != nil {
		diags.AddError("API Error", fmt.Sprintf("Failed to create upload request: %v", err))
		return
	}

	var uploadResponse struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(result, &uploadResponse); err != nil {
		diags.AddError("Parse Error", fmt.Sprintf("Failed to parse upload response: %v", err))
		return
	}

	var chainKey string
	var chainID int64
	for i := 0; i < defaultRetryConfig.UploadMaxRetries; i++ {
		time.Sleep(defaultRetryConfig.UploadInitialDelay)
		if i > 0 {
			time.Sleep(defaultRetryConfig.UploadRetryDelay)
		}

		detail, err := r.getRequestDetails(ctx, path, uploadResponse.ID)
		if err != nil {
			tflog.Info(ctx, fmt.Sprintf("Retry %d: failed to get request details: %v", i+1, err))
			continue
		}

		if len(detail.Result.Chains) > 0 {
			chainKey = detail.Result.Chains[0].ChainKey
			chainID = detail.Result.Chains[0].ChainID
			break
		}
	}

	if chainKey == "" {
		diags.AddError("Timeout Error", "Failed to get chain_key after retries")
		return
	}

	installParams := []interface{}{
		uploadResponse.ID,
		chainKey,
		chainID,
	}
	installResult, err := r.client.MakeRequest(ctx, path, "certrequest_install", installParams)
	if err != nil {
		diags.AddError("API Error", fmt.Sprintf("Failed to install certificate: %v", err))
		return
	}

	tflog.Debug(ctx, "Install certificate response", map[string]interface{}{
		"raw_response": string(installResult),
	})

	var certificateID int64
	if err := json.Unmarshal(installResult, &certificateID); err == nil {
		tflog.Debug(ctx, "Parsed certificate ID from direct number", map[string]interface{}{
			"certificate_id": certificateID,
		})
	} else {
		var idResponse struct {
			CertificateID int64 `json:"result"`
		}
		if err := json.Unmarshal(installResult, &idResponse); err != nil {
			diags.AddError("Parse Error", fmt.Sprintf("Failed to parse install response (tried both formats): %v", err))
			return
		}
		certificateID = idResponse.CertificateID
		tflog.Debug(ctx, "Parsed certificate ID from struct", map[string]interface{}{
			"certificate_id": certificateID,
		})
	}

	cert, err := r.getCertificateDetails(ctx, path, certificateID)
	if err != nil {
		diags.AddError("API Error", fmt.Sprintf("Failed to get certificate details (ID: %d): %v", certificateID, err))
		return
	}

	r.mapCertificateToModel(ctx, cert, plan, diags)
}

func (r *ClientCertificateResource) handleLetsEncryptCertificate(ctx context.Context, path string, plan *ClientCertificateResourceModel, diags *diag.Diagnostics) {
	var hostnames []string
	if !plan.Hostnames.IsNull() {
		d := plan.Hostnames.ElementsAs(ctx, &hostnames, false)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
	}

	params := []interface{}{
		plan.DomainID.ValueInt64(),
		hostnames,
	}
	result, err := r.client.MakeRequest(ctx, path, "certrequest_le", params)
	if err != nil {
		diags.AddError("API Error", fmt.Sprintf("Failed to create Let's Encrypt request: %v", err))
		return
	}

	var leResponse struct {
		ID        int64    `json:"id"`
		Hostnames []string `json:"hostnames"`
	}
	if err := json.Unmarshal(result, &leResponse); err != nil {
		diags.AddError("Parse Error", fmt.Sprintf("Failed to parse Let's Encrypt response: %v", err))
		return
	}

	var certificate *certificateDetails
	for i := 0; i < defaultRetryConfig.LetsEncryptMaxRetries; i++ {
		time.Sleep(defaultRetryConfig.LetsEncryptInitialDelay)
		if i > 0 {
			time.Sleep(defaultRetryConfig.LetsEncryptRetryDelay)
		}

		cert, err := r.findLECertificate(ctx, path, leResponse.Hostnames)
		if err != nil {
			tflog.Info(ctx, fmt.Sprintf("Retry %d: failed to find Let's Encrypt certificate: %v", i+1, err))
			continue
		}

		if cert != nil {
			certificate = cert
			break
		}
	}

	if certificate == nil {
		diags.AddError("Timeout Error", "Failed to find issued Let's Encrypt certificate after retries")
		return
	}

	fullCert, err := r.getCertificateDetails(ctx, path, certificate.ID)
	if err != nil {
		diags.AddError("API Error", fmt.Sprintf("Failed to get certificate details (ID: %d): %v", certificate.ID, err))
		return
	}

	r.mapCertificateToModel(ctx, fullCert, plan, diags)
}

func (r *ClientCertificateResource) findLECertificate(ctx context.Context, path string, expectedHostnames []string) (*certificateDetails, error) {
	result, err := r.client.MakeRequest(ctx, path, "certificate_list", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	var certs []certificateDetails
	if err := json.Unmarshal(result, &certs); err != nil {
		return nil, fmt.Errorf("failed to parse certificates list: %w", err)
	}

	for _, cert := range certs {
		if cert.Type == "letsencrypt" && stringSlicesEqual(cert.Hostnames, expectedHostnames) {
			return &cert, nil
		}
	}

	return nil, nil
}

func (r *ClientCertificateResource) getRequestDetails(ctx context.Context, path string, requestID int64) (*requestDetails, error) {
	result, err := r.client.MakeRequest(ctx, path, "certrequest_get", []int64{requestID})
	if err != nil {
		return nil, fmt.Errorf("failed to get request details (ID: %d): %w", requestID, err)
	}

	var details requestDetails
	if err := json.Unmarshal(result, &details); err != nil {
		return nil, fmt.Errorf("failed to parse request details (ID: %d): %w", requestID, err)
	}

	return &details, nil
}

func (r *ClientCertificateResource) getCertificateDetails(ctx context.Context, path string, certID int64) (*certificateDetails, error) {
	result, err := r.client.MakeRequest(ctx, path, "certificate_get", []int64{certID})
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate details (ID: %d): %w", certID, err)
	}

	var cert certificateDetails
	if err := json.Unmarshal(result, &cert); err != nil {
		return nil, fmt.Errorf("failed to parse certificate details (ID: %d): %w", certID, err)
	}

	if cert.Hostnames == nil {
		cert.Hostnames = []string{}
	}
	if cert.Certificates == nil {
		cert.Certificates = []certDetails{}
	}
	if cert.Links == nil {
		cert.Links = []linkDetails{}
	}

	return &cert, nil
}

func (r *ClientCertificateResource) mapCertificateToModel(ctx context.Context, cert *certificateDetails, model *ClientCertificateResourceModel, diags *diag.Diagnostics) {
	model.ID = types.Int64Value(cert.ID)
	model.Type = types.StringValue(cert.Type)
	model.NotValidBefore = types.Int64Value(cert.NotValidBefore)
	model.NotValidAfter = types.Int64Value(cert.NotValidAfter)
	model.ProtectKey = types.BoolValue(cert.ProtectKey)

	if cert.DomainID != nil {
		model.DomainID = types.Int64Value(*cert.DomainID)
	} else {
		model.DomainID = types.Int64Null()
	}

	switch v := cert.Autoupdate.(type) {
	case bool:
		model.Autoupdate = types.StringValue(fmt.Sprintf("%t", v))
	case string:
		model.Autoupdate = types.StringValue(v)
	case nil:
		model.Autoupdate = types.StringNull()
	default:
		model.Autoupdate = types.StringValue(fmt.Sprintf("%v", v))
	}

	model.Hostnames = toStringList(cert.Hostnames, diags)
	if diags.HasError() {
		return
	}

	certModels := make([]CertDetailModel, len(cert.Certificates))
	for i, c := range cert.Certificates {
		certModels[i] = CertDetailModel{
			Type: types.StringValue(c.Type),
			Cert: types.StringValue(c.Cert),
			Key:  types.StringValue(c.Key),
		}
	}
	model.Certificates = toCertificateList(ctx, certModels, diags)
	if diags.HasError() {
		return
	}

	model.Links = toLinkList(ctx, cert.Links, diags)
	if diags.HasError() {
		return
	}
}

func restoreSensitiveCertificates(ctx context.Context, originalCerts []CertDetailModel, currentCerts types.List, diags *diag.Diagnostics) types.List {
	var newCerts []CertDetailModel
	if !currentCerts.IsNull() {
		d := currentCerts.ElementsAs(ctx, &newCerts, false)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{
				"type": types.StringType,
				"cert": types.StringType,
				"key":  types.StringType,
			}})
		}
	}

	for i := range newCerts {
		if i < len(originalCerts) {
			newCerts[i].Key = originalCerts[i].Key
			newCerts[i].Cert = originalCerts[i].Cert
		}
	}

	return toCertificateList(ctx, newCerts, diags)
}

func toStringList(values []string, diags *diag.Diagnostics) types.List {
	elems := make([]attr.Value, len(values))
	for i, v := range values {
		elems[i] = types.StringValue(v)
	}
	list, d := types.ListValue(types.StringType, elems)
	diags.Append(d...)
	return list
}

func toCertificateList(ctx context.Context, certs []CertDetailModel, diags *diag.Diagnostics) types.List {
	elems := make([]attr.Value, len(certs))
	for i, c := range certs {
		obj, d := types.ObjectValueFrom(ctx, map[string]attr.Type{
			"type": types.StringType,
			"cert": types.StringType,
			"key":  types.StringType,
		}, c)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{
				"type": types.StringType,
				"cert": types.StringType,
				"key":  types.StringType,
			}})
		}
		elems[i] = obj
	}

	list, d := types.ListValue(types.ObjectType{AttrTypes: map[string]attr.Type{
		"type": types.StringType,
		"cert": types.StringType,
		"key":  types.StringType,
	}}, elems)
	diags.Append(d...)
	return list
}

func toLinkList(ctx context.Context, links []linkDetails, diags *diag.Diagnostics) types.List {
	elems := make([]attr.Value, len(links))
	for i, l := range links {
		link := CertLinkModel{
			LinkID:      types.Int64Value(l.LinkID),
			Port:        types.Int64Value(l.Port),
			DomainID:    types.Int64Value(l.DomainID),
			Certificate: types.Int64Value(l.Certificate),
		}
		if l.Hostname != nil {
			link.Hostname = types.StringValue(*l.Hostname)
		} else {
			link.Hostname = types.StringNull()
		}

		obj, d := types.ObjectValueFrom(ctx, map[string]attr.Type{
			"link_id":     types.Int64Type,
			"port":        types.Int64Type,
			"hostname":    types.StringType,
			"domain_id":   types.Int64Type,
			"certificate": types.Int64Type,
		}, link)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{
				"link_id":     types.Int64Type,
				"port":        types.Int64Type,
				"hostname":    types.StringType,
				"domain_id":   types.Int64Type,
				"certificate": types.Int64Type,
			}})
		}
		elems[i] = obj
	}

	list, d := types.ListValue(types.ObjectType{AttrTypes: map[string]attr.Type{
		"link_id":     types.Int64Type,
		"port":        types.Int64Type,
		"hostname":    types.StringType,
		"domain_id":   types.Int64Type,
		"certificate": types.Int64Type,
	}}, elems)
	diags.Append(d...)
	return list
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
