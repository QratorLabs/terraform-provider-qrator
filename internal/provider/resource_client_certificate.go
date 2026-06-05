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

// certDetailAttrTypes is the attr.Type map for CertDetailModel objects.
var certDetailAttrTypes = map[string]attr.Type{
	"type": types.StringType,
	"cert": types.StringType,
	"key":  types.StringType,
}

// certLinkAttrTypes is the attr.Type map for CertLinkModel objects.
var certLinkAttrTypes = map[string]attr.Type{
	"link_id":     types.Int64Type,
	"port":        types.Int64Type,
	"hostname":    types.StringType,
	"domain_id":   types.Int64Type,
	"certificate": types.Int64Type,
}

const (
	CertTypeUpload      = "upload"
	CertTypeLetsEncrypt = "letsencrypt"

	leMaxHostnames = 12
)

type ClientCertificateResource struct {
	client client.QratorClientAPI
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
	RequestID      types.Int64  `tfsdk:"request_id"`
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
	ID     int64    `json:"id"`
	Status string   `json:"status"`
	Errors []string `json:"errors"`
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
			"request_id": schema.Int64Attribute{
				Description: "The ID of the certificate request (certrequest_upload or certrequest_le). Stored to allow cleanup on delete.",
				Computed:    true,
				Optional:    true,
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
	if !plan.Certificates.IsNull() && !plan.Certificates.IsUnknown() {
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

	// Preserve request_id — it comes from Create and is not returned by certificate_get.
	requestID := state.RequestID

	r.mapCertificateToModel(ctx, cert, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	state.RequestID = requestID

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

	// Remove the certrequest if we have its ID (not available after import).
	if !state.RequestID.IsNull() && !state.RequestID.IsUnknown() {
		_, err := r.client.MakeRequest(ctx, path, "certrequest_remove", []int64{state.RequestID.ValueInt64()})
		if err != nil {
			// Log but don't fail — the certificate itself is already removed.
			tflog.Warn(ctx, "Failed to remove certificate request", map[string]interface{}{
				"request_id": state.RequestID.ValueInt64(),
				"error":      err.Error(),
			})
		}
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
	state.RequestID = types.Int64Null() // not available after import
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
		if len(hostnames) > leMaxHostnames {
			return fmt.Errorf("letsencrypt certificates support at most %d hostnames, got %d", leMaxHostnames, len(hostnames))
		}
	}

	return nil
}

// waitForCertRequest polls certrequest_get until status == "done", then returns the first chain's key and ID.
// It respects context cancellation so that Ctrl+C during terraform apply is handled promptly.
func (r *ClientCertificateResource) waitForCertRequest(
	ctx context.Context,
	path string,
	requestID int64,
	initialDelay, retryDelay time.Duration,
	maxRetries int,
) (chainKey string, chainID int64, err error) {
	sleep := func(d time.Duration) error {
		select {
		case <-time.After(d):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if err := sleep(initialDelay); err != nil {
		return "", 0, err
	}

	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			if err := sleep(retryDelay); err != nil {
				return "", 0, err
			}
		}

		detail, err := r.getRequestDetails(ctx, path, requestID)
		if err != nil {
			tflog.Info(ctx, fmt.Sprintf("certrequest poll %d/%d: error fetching details: %v", i+1, maxRetries, err))
			continue
		}

		tflog.Debug(ctx, fmt.Sprintf("certrequest poll %d/%d: status=%q", i+1, maxRetries, detail.Status))

		if detail.Status != "done" {
			continue
		}

		if len(detail.Errors) > 0 {
			return "", 0, fmt.Errorf("certificate request failed: %v", detail.Errors)
		}
		if len(detail.Result.Chains) == 0 {
			return "", 0, fmt.Errorf("certificate request completed but returned no chains")
		}

		return detail.Result.Chains[0].ChainKey, detail.Result.Chains[0].ChainID, nil
	}

	return "", 0, fmt.Errorf("timed out waiting for certificate request %d to complete", requestID)
}

// installCertRequest calls certrequest_install and returns the resulting certificate ID.
func (r *ClientCertificateResource) installCertRequest(ctx context.Context, path string, requestID int64, chainKey string, chainID int64) (int64, error) {
	installResult, err := r.client.MakeRequest(ctx, path, "certrequest_install", []interface{}{
		requestID,
		chainKey,
		chainID,
	})
	if err != nil {
		return 0, fmt.Errorf("certrequest_install: %w", err)
	}

	tflog.Debug(ctx, "certrequest_install response", map[string]interface{}{
		"raw": string(installResult),
	})

	// API returns a plain number.
	var certificateID int64
	if err := json.Unmarshal(installResult, &certificateID); err != nil {
		return 0, fmt.Errorf("failed to parse certrequest_install response: %w", err)
	}

	return certificateID, nil
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

	result, err := r.client.MakeRequest(ctx, path, "certrequest_upload", []string{
		certDetails[0].Cert.ValueString(),
		certDetails[0].Key.ValueString(),
	})
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

	requestID := uploadResponse.ID
	chainKey, chainID, err := r.waitForCertRequest(
		ctx, path, requestID,
		defaultRetryConfig.UploadInitialDelay,
		defaultRetryConfig.UploadRetryDelay,
		defaultRetryConfig.UploadMaxRetries,
	)
	if err != nil {
		diags.AddError("Certificate Request Error", fmt.Sprintf("Upload request (ID: %d) failed: %v", requestID, err))
		return
	}

	certificateID, err := r.installCertRequest(ctx, path, requestID, chainKey, chainID)
	if err != nil {
		diags.AddError("API Error", fmt.Sprintf("Failed to install certificate: %v", err))
		return
	}

	plan.RequestID = types.Int64Value(requestID)

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

	result, err := r.client.MakeRequest(ctx, path, "certrequest_le", []interface{}{
		plan.DomainID.ValueInt64(),
		hostnames,
	})
	if err != nil {
		diags.AddError("API Error", fmt.Sprintf("Failed to create Let's Encrypt request: %v", err))
		return
	}

	var leResponse struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(result, &leResponse); err != nil {
		diags.AddError("Parse Error", fmt.Sprintf("Failed to parse Let's Encrypt response: %v", err))
		return
	}

	requestID := leResponse.ID
	chainKey, chainID, err := r.waitForCertRequest(
		ctx, path, requestID,
		defaultRetryConfig.LetsEncryptInitialDelay,
		defaultRetryConfig.LetsEncryptRetryDelay,
		defaultRetryConfig.LetsEncryptMaxRetries,
	)
	if err != nil {
		diags.AddError("Certificate Request Error", fmt.Sprintf("Let's Encrypt request (ID: %d) failed: %v", requestID, err))
		return
	}

	certificateID, err := r.installCertRequest(ctx, path, requestID, chainKey, chainID)
	if err != nil {
		diags.AddError("API Error", fmt.Sprintf("Failed to install Let's Encrypt certificate: %v", err))
		return
	}

	plan.RequestID = types.Int64Value(requestID)

	cert, err := r.getCertificateDetails(ctx, path, certificateID)
	if err != nil {
		diags.AddError("API Error", fmt.Sprintf("Failed to get certificate details (ID: %d): %v", certificateID, err))
		return
	}

	r.mapCertificateToModel(ctx, cert, plan, diags)
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
			return types.ListNull(types.ObjectType{AttrTypes: certDetailAttrTypes})
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
		obj, d := types.ObjectValueFrom(ctx, certDetailAttrTypes, c)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: certDetailAttrTypes})
		}
		elems[i] = obj
	}

	list, d := types.ListValue(types.ObjectType{AttrTypes: certDetailAttrTypes}, elems)
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

		obj, d := types.ObjectValueFrom(ctx, certLinkAttrTypes, link)
		diags.Append(d...)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: certLinkAttrTypes})
		}
		elems[i] = obj
	}

	list, d := types.ListValue(types.ObjectType{AttrTypes: certLinkAttrTypes}, elems)
	diags.Append(d...)
	return list
}

