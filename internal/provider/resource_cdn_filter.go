package provider

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// ---------------------------------------------------------------------------
// Wire format (CdnFilter, see https://api.qrator.net/schema/CdnFilter.json)
// ---------------------------------------------------------------------------

// apiCdnFilter is the payload of filter_get / filter_set. filter_set replaces
// the whole filter, so every section is always sent (null when empty).
type apiCdnFilter struct {
	Skip      *apiFilterSkip        `json:"skip"`
	Geo       *apiFilterStringRules `json:"geo"`
	IP        *apiFilterStringRules `json:"ip"`
	URI       *apiFilterRegexRules  `json:"uri"`
	UserAgent *apiFilterRegexRules  `json:"user_agent"`
	Referer   *apiFilterRegexRules  `json:"referer"`
	Method    *apiFilterStringRules `json:"method"`
}

type apiFilterSkip struct {
	IP []string `json:"ip"`
}

// apiFilterStringRules is the shape of the geo, ip and method sections.
type apiFilterStringRules struct {
	Allow                           []string `json:"allow"`
	AllowRuleBlockingHTTPStatusCode *int64   `json:"allow_rule_blocking_http_status_code"`
	Deny                            []string `json:"deny"`
	DenyRuleBlockingHTTPStatusCode  *int64   `json:"deny_rule_blocking_http_status_code"`
}

// apiFilterRegexRules is the shape of the uri, user_agent and referer sections.
// The block_without_* flags exist only in their own section, hence omitempty.
type apiFilterRegexRules struct {
	Allow                           []apiFilterRegex         `json:"allow"`
	AllowRuleBlockingHTTPStatusCode *int64                   `json:"allow_rule_blocking_http_status_code"`
	Deny                            []apiFilterRegexWithCode `json:"deny"`
	BlockWithoutUserAgent           *bool                    `json:"block_without_user_agent,omitempty"`
	BlockWithoutReferer             *bool                    `json:"block_without_referer,omitempty"`
}

type apiFilterRegex struct {
	Regex string `json:"regex"`
}

type apiFilterRegexWithCode struct {
	Regex          string `json:"regex"`
	HTTPStatusCode int64  `json:"http_status_code"`
}

// ---------------------------------------------------------------------------
// Terraform models
// ---------------------------------------------------------------------------

// CDNAccessFilterModel is the model for the access_filter attribute.
type CDNAccessFilterModel struct {
	SkipIPs   types.Set                  `tfsdk:"skip_ips"`
	IP        *CDNFilterListRulesModel   `tfsdk:"ip"`
	Geo       *CDNFilterListRulesModel   `tfsdk:"geo"`
	Method    *CDNFilterListRulesModel   `tfsdk:"method"`
	URI       *CDNFilterURIRulesModel    `tfsdk:"uri"`
	UserAgent *CDNFilterHeaderRulesModel `tfsdk:"user_agent"`
	Referer   *CDNFilterHeaderRulesModel `tfsdk:"referer"`
}

// CDNFilterListRulesModel is the model for the ip, geo and method sections.
type CDNFilterListRulesModel struct {
	Allow           types.Set   `tfsdk:"allow"`
	AllowStatusCode types.Int64 `tfsdk:"allow_status_code"`
	Deny            types.Set   `tfsdk:"deny"`
	DenyStatusCode  types.Int64 `tfsdk:"deny_status_code"`
}

// CDNFilterURIRulesModel is the model for the uri section.
type CDNFilterURIRulesModel struct {
	Allow           types.List  `tfsdk:"allow"`
	AllowStatusCode types.Int64 `tfsdk:"allow_status_code"`
	Deny            types.List  `tfsdk:"deny"`
}

// CDNFilterHeaderRulesModel is the model for the user_agent and referer sections.
type CDNFilterHeaderRulesModel struct {
	Allow           types.List  `tfsdk:"allow"`
	AllowStatusCode types.Int64 `tfsdk:"allow_status_code"`
	Deny            types.List  `tfsdk:"deny"`
	BlockEmpty      types.Bool  `tfsdk:"block_empty"`
}

// CDNFilterDenyRegexModel is one entry of a regex deny list.
type CDNFilterDenyRegexModel struct {
	Regex      types.String `tfsdk:"regex"`
	StatusCode types.Int64  `tfsdk:"status_code"`
}

var filterDenyRegexAttrTypes = map[string]attr.Type{
	"regex":       types.StringType,
	"status_code": types.Int64Type,
}

var filterListRulesAttrTypes = map[string]attr.Type{
	"allow":             types.SetType{ElemType: types.StringType},
	"allow_status_code": types.Int64Type,
	"deny":              types.SetType{ElemType: types.StringType},
	"deny_status_code":  types.Int64Type,
}

var filterURIRulesAttrTypes = map[string]attr.Type{
	"allow":             types.ListType{ElemType: types.StringType},
	"allow_status_code": types.Int64Type,
	"deny":              types.ListType{ElemType: types.ObjectType{AttrTypes: filterDenyRegexAttrTypes}},
}

var filterHeaderRulesAttrTypes = map[string]attr.Type{
	"allow":             types.ListType{ElemType: types.StringType},
	"allow_status_code": types.Int64Type,
	"deny":              types.ListType{ElemType: types.ObjectType{AttrTypes: filterDenyRegexAttrTypes}},
	"block_empty":       types.BoolType,
}

var accessFilterAttrTypes = map[string]attr.Type{
	"skip_ips":   types.SetType{ElemType: types.StringType},
	"ip":         types.ObjectType{AttrTypes: filterListRulesAttrTypes},
	"geo":        types.ObjectType{AttrTypes: filterListRulesAttrTypes},
	"method":     types.ObjectType{AttrTypes: filterListRulesAttrTypes},
	"uri":        types.ObjectType{AttrTypes: filterURIRulesAttrTypes},
	"user_agent": types.ObjectType{AttrTypes: filterHeaderRulesAttrTypes},
	"referer":    types.ObjectType{AttrTypes: filterHeaderRulesAttrTypes},
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const filterMaxItems = 500

var (
	countryCodeRE = regexp.MustCompile(`^([A-Z]{2}|A1|A2|O1)$`)
	httpMethods   = []string{"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"}
)

// filterStatusCodeValidators restricts blocking status codes to the values the
// API accepts: 200–599 except 204, 300–308, 407, 426 and 511.
func filterStatusCodeValidators() []validator.Int64 {
	return []validator.Int64{
		int64validator.Between(200, 599),
		int64validator.NoneOf(204, 300, 301, 302, 303, 304, 305, 306, 307, 308, 407, 426, 511),
	}
}

func filterStatusCodeAttr(description string) schema.Int64Attribute {
	return schema.Int64Attribute{
		Description: description + " If not set, CDN responds with 403.",
		Optional:    true,
		Validators:  filterStatusCodeValidators(),
	}
}

func filterStringSetAttr(description string, maxItems int, elem ...validator.String) schema.SetAttribute {
	return schema.SetAttribute{
		Description: description,
		Optional:    true,
		ElementType: types.StringType,
		Validators: []validator.Set{
			setvalidator.SizeAtMost(maxItems),
			setvalidator.ValueStringsAre(elem...),
		},
	}
}

func filterListRulesAttr(what, valueFormat string, maxItems int, elem ...validator.String) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Description: fmt.Sprintf("Filter by %s.", what),
		Optional:    true,
		Attributes: map[string]schema.Attribute{
			"allow": filterStringSetAttr(
				fmt.Sprintf("Allow list of %s. When not empty, requests matching none of them are blocked with `allow_status_code`.", valueFormat),
				maxItems, elem...),
			"allow_status_code": filterStatusCodeAttr("HTTP status code for requests blocked by the allow list."),
			"deny": filterStringSetAttr(
				fmt.Sprintf("Deny list of %s. Matching requests are blocked with `deny_status_code`.", valueFormat),
				maxItems, elem...),
			"deny_status_code": filterStatusCodeAttr("HTTP status code for requests blocked by the deny list."),
		},
	}
}

func filterRegexAllowAttr(header string) schema.ListAttribute {
	return schema.ListAttribute{
		Description: fmt.Sprintf("Allow list of regular expressions for %s. When not empty, requests matching none of them are blocked with `allow_status_code`.", header),
		Optional:    true,
		ElementType: types.StringType,
		Validators: []validator.List{
			listvalidator.SizeAtMost(filterMaxItems),
			listvalidator.UniqueValues(),
			listvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1)),
		},
	}
}

func filterRegexDenyAttr(header string) schema.ListNestedAttribute {
	return schema.ListNestedAttribute{
		Description: fmt.Sprintf("Deny list of regular expressions for %s. Entries are checked in order: the first matching entry blocks the request with its status code.", header),
		Optional:    true,
		Validators: []validator.List{
			listvalidator.SizeAtMost(filterMaxItems),
			listvalidator.UniqueValues(),
		},
		NestedObject: schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"regex": schema.StringAttribute{
					Description: "Regular expression.",
					Required:    true,
					Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
				},
				"status_code": schema.Int64Attribute{
					Description: "HTTP status code returned for matching requests.",
					Required:    true,
					Validators:  filterStatusCodeValidators(),
				},
			},
		},
	}
}

func filterHeaderRulesAttr(header string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Description: fmt.Sprintf("Filter by the `%s` header.", header),
		Optional:    true,
		Attributes: map[string]schema.Attribute{
			"allow":             filterRegexAllowAttr("the `" + header + "` header"),
			"allow_status_code": filterStatusCodeAttr("HTTP status code for requests blocked by the allow list."),
			"deny":              filterRegexDenyAttr("the `" + header + "` header"),
			"block_empty": schema.BoolAttribute{
				Description: fmt.Sprintf("Block requests without the `%s` header. Defaults to `false`.", header),
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
		},
	}
}

// accessFilterSchemaAttribute returns the schema of qrator_cdn.access_filter.
func accessFilterSchemaAttribute() schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Description: "CDN access filter. Filters are applied in order: ip, geo, method, uri, user_agent, referer; " +
			"the first one that blocks a request determines the response code. Requests from `skip_ips` bypass all filters. " +
			"When set, Terraform manages the whole filter: sections not described here are cleared. " +
			"When omitted, the filter is not managed by Terraform; removing the attribute stops managing the filter " +
			"and leaves it unchanged in Qrator.",
		// Deliberately not Computed: for an unset Optional+Computed object whose
		// prior state holds non-computed values, Terraform core proposes null,
		// which would turn every plan into an in-place update once the filter
		// is changed outside Terraform. Unmanaged filter = null in state.
		Optional: true,
		Attributes: map[string]schema.Attribute{
			"skip_ips": filterStringSetAttr(
				"Client IPs or CIDR networks that bypass all other filters.",
				filterMaxItems, ipOrCIDRValidator{}),
			"ip": filterListRulesAttr("client IP", "IPs or CIDR networks (canonical form, prefix /14 or longer)",
				filterMaxItems, ipOrCIDRValidator{}),
			"geo": filterListRulesAttr("client country", "ISO 3166-1 alpha-2 country codes in upper case (`A1`, `A2`, `O1` are also accepted)",
				filterMaxItems, stringvalidator.RegexMatches(countryCodeRE, "must be an upper-case ISO 3166-1 alpha-2 country code")),
			"method": filterListRulesAttr("HTTP method", "HTTP methods in upper case",
				len(httpMethods), stringvalidator.OneOf(httpMethods...)),
			"uri": schema.SingleNestedAttribute{
				Description: "Filter by the requested URL.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"allow":             filterRegexAllowAttr("the requested URL"),
					"allow_status_code": filterStatusCodeAttr("HTTP status code for requests blocked by the allow list."),
					"deny":              filterRegexDenyAttr("the requested URL"),
				},
			},
			"user_agent": filterHeaderRulesAttr("User-Agent"),
			"referer":    filterHeaderRulesAttr("Referer"),
		},
	}
}

// ipOrCIDRValidator accepts an IP address or CIDR network written in canonical
// form (the API normalises addresses, so any other spelling would cause drift).
type ipOrCIDRValidator struct{}

func (v ipOrCIDRValidator) Description(_ context.Context) string {
	return "value must be an IP address or CIDR network in canonical form with prefix /14 or longer"
}

func (v ipOrCIDRValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v ipOrCIDRValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if msg := checkIPOrCIDR(req.ConfigValue.ValueString()); msg != "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid IP address or network", msg)
	}
}

// checkIPOrCIDR returns an error message, or "" if s is valid.
func checkIPOrCIDR(s string) string {
	if addr, err := netip.ParseAddr(s); err == nil {
		if addr.Zone() != "" {
			return fmt.Sprintf("%q: IPv6 zones are not allowed", s)
		}
		if canon := addr.String(); canon != s {
			return fmt.Sprintf("%q is not in canonical form, use %q", s, canon)
		}
		return ""
	}
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return fmt.Sprintf("%q is not a valid IP address or CIDR network", s)
	}
	if prefix.Bits() < 14 {
		return fmt.Sprintf("%q: prefix must be /14 or longer", s)
	}
	if canon := prefix.Masked().String(); canon != s {
		return fmt.Sprintf("%q is not in canonical form, use %q", s, canon)
	}
	return ""
}

// ---------------------------------------------------------------------------
// Model -> API
// ---------------------------------------------------------------------------

// accessFilterToAPI converts the access_filter model to a filter_set payload.
// Sections without any rules are sent as null.
func accessFilterToAPI(ctx context.Context, m CDNAccessFilterModel) (apiCdnFilter, diag.Diagnostics) {
	var diags diag.Diagnostics
	var out apiCdnFilter

	if skip := setStrings(ctx, m.SkipIPs, &diags); len(skip) > 0 {
		out.Skip = &apiFilterSkip{IP: skip}
	}
	out.IP = listRulesToAPI(ctx, m.IP, &diags)
	out.Geo = listRulesToAPI(ctx, m.Geo, &diags)
	out.Method = listRulesToAPI(ctx, m.Method, &diags)
	if m.URI != nil {
		out.URI = regexRulesToAPI(ctx, m.URI.Allow, m.URI.AllowStatusCode, m.URI.Deny, &diags)
	}
	if m.UserAgent != nil {
		out.UserAgent = regexRulesToAPI(ctx, m.UserAgent.Allow, m.UserAgent.AllowStatusCode, m.UserAgent.Deny, &diags)
		if block := m.UserAgent.BlockEmpty.ValueBool(); block || out.UserAgent != nil {
			out.UserAgent = ensureRegexRules(out.UserAgent)
			out.UserAgent.BlockWithoutUserAgent = &block
		}
	}
	if m.Referer != nil {
		out.Referer = regexRulesToAPI(ctx, m.Referer.Allow, m.Referer.AllowStatusCode, m.Referer.Deny, &diags)
		if block := m.Referer.BlockEmpty.ValueBool(); block || out.Referer != nil {
			out.Referer = ensureRegexRules(out.Referer)
			out.Referer.BlockWithoutReferer = &block
		}
	}
	return out, diags
}

func listRulesToAPI(ctx context.Context, m *CDNFilterListRulesModel, diags *diag.Diagnostics) *apiFilterStringRules {
	if m == nil {
		return nil
	}
	allow := setStrings(ctx, m.Allow, diags)
	deny := setStrings(ctx, m.Deny, diags)
	if len(allow) == 0 && len(deny) == 0 {
		return nil
	}
	return &apiFilterStringRules{
		Allow:                           allow,
		AllowRuleBlockingHTTPStatusCode: int64PtrOrNil(m.AllowStatusCode),
		Deny:                            deny,
		DenyRuleBlockingHTTPStatusCode:  int64PtrOrNil(m.DenyStatusCode),
	}
}

// regexRulesToAPI returns nil when neither list has entries.
func regexRulesToAPI(ctx context.Context, allowList types.List, allowCode types.Int64, denyList types.List, diags *diag.Diagnostics) *apiFilterRegexRules {
	var allowStrs []string
	if !IsNullOrUnknown(allowList) {
		diags.Append(allowList.ElementsAs(ctx, &allowStrs, false)...)
	}
	var denyModels []CDNFilterDenyRegexModel
	if !IsNullOrUnknown(denyList) {
		diags.Append(denyList.ElementsAs(ctx, &denyModels, false)...)
	}
	if len(allowStrs) == 0 && len(denyModels) == 0 {
		return nil
	}
	out := ensureRegexRules(nil)
	for _, s := range allowStrs {
		out.Allow = append(out.Allow, apiFilterRegex{Regex: s})
	}
	out.AllowRuleBlockingHTTPStatusCode = int64PtrOrNil(allowCode)
	for _, d := range denyModels {
		out.Deny = append(out.Deny, apiFilterRegexWithCode{Regex: d.Regex.ValueString(), HTTPStatusCode: d.StatusCode.ValueInt64()})
	}
	return out
}

// ensureRegexRules returns r, or a new section with non-nil lists: the API
// schema allows null only for status codes, so lists are sent as [] when empty.
func ensureRegexRules(r *apiFilterRegexRules) *apiFilterRegexRules {
	if r != nil {
		return r
	}
	return &apiFilterRegexRules{Allow: []apiFilterRegex{}, Deny: []apiFilterRegexWithCode{}}
}

// setStrings returns the elements of a string set as a non-nil slice.
func setStrings(ctx context.Context, s types.Set, diags *diag.Diagnostics) []string {
	out := []string{}
	if !IsNullOrUnknown(s) {
		diags.Append(s.ElementsAs(ctx, &out, false)...)
	}
	return out
}

func int64PtrOrNil(v types.Int64) *int64 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	n := v.ValueInt64()
	return &n
}

// ---------------------------------------------------------------------------
// API -> model
// ---------------------------------------------------------------------------

// accessFilterFromAPI converts a filter_get result into the access_filter model.
//
// ref is the prior plan or state (nil if unknown). It is used to keep the
// user's representation of "nothing configured": the API returns empty
// sections and lists as null, while the configuration may spell them as {} or
// []. Whenever the API and ref both have no rules for a part of the filter,
// the ref value is kept so that no spurious diff appears. Regex allow lists are
// reordered to follow ref (their order has no effect); regex deny lists keep
// the API order, because the first matching entry determines the status code
// and a reordering must show up as a diff.
func accessFilterFromAPI(ctx context.Context, api apiCdnFilter, ref *CDNAccessFilterModel) (CDNAccessFilterModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	if ref == nil {
		ref = &CDNAccessFilterModel{}
	}

	var out CDNAccessFilterModel
	var skip []string
	if api.Skip != nil {
		skip = api.Skip.IP
	}
	out.SkipIPs = stringSetFromAPI(ctx, skip, ref.SkipIPs, &diags)
	out.IP = listRulesFromAPI(ctx, api.IP, ref.IP, &diags)
	out.Geo = listRulesFromAPI(ctx, api.Geo, ref.Geo, &diags)
	out.Method = listRulesFromAPI(ctx, api.Method, ref.Method, &diags)
	out.URI = uriRulesFromAPI(ctx, api.URI, ref.URI, &diags)
	out.UserAgent = headerRulesFromAPI(ctx, api.UserAgent, blockWithoutUA, ref.UserAgent, &diags)
	out.Referer = headerRulesFromAPI(ctx, api.Referer, blockWithoutReferer, ref.Referer, &diags)
	return out, diags
}

// stringSetFromAPI builds a set from API values, keeping ref when both are empty.
func stringSetFromAPI(ctx context.Context, values []string, ref types.Set, diags *diag.Diagnostics) types.Set {
	if len(values) == 0 {
		if len(ref.Elements()) == 0 {
			return normalizeNullSet(ref)
		}
		return types.SetNull(types.StringType)
	}
	s, d := types.SetValueFrom(ctx, types.StringType, values)
	diags.Append(d...)
	return s
}

func listRulesEmpty(m *CDNFilterListRulesModel) bool {
	return m == nil || (len(m.Allow.Elements()) == 0 && len(m.Deny.Elements()) == 0)
}

func listRulesFromAPI(ctx context.Context, api *apiFilterStringRules, ref *CDNFilterListRulesModel, diags *diag.Diagnostics) *CDNFilterListRulesModel {
	apiEmpty := api == nil || (len(api.Allow) == 0 && len(api.Deny) == 0)
	if apiEmpty && listRulesEmpty(ref) {
		return ref
	}
	if api == nil {
		return nil
	}
	if ref == nil {
		ref = &CDNFilterListRulesModel{}
	}
	out := &CDNFilterListRulesModel{}
	out.Allow, out.AllowStatusCode = stringRuleFromAPI(ctx, api.Allow, api.AllowRuleBlockingHTTPStatusCode, ref.Allow, ref.AllowStatusCode, diags)
	out.Deny, out.DenyStatusCode = stringRuleFromAPI(ctx, api.Deny, api.DenyRuleBlockingHTTPStatusCode, ref.Deny, ref.DenyStatusCode, diags)
	return out
}

// stringRuleFromAPI converts one allow or deny rule (list + status code). When
// neither the API nor ref has entries, the ref representation is kept: a
// status code without entries has no effect.
func stringRuleFromAPI(ctx context.Context, values []string, code *int64, refSet types.Set, refCode types.Int64, diags *diag.Diagnostics) (types.Set, types.Int64) {
	if len(values) == 0 && len(refSet.Elements()) == 0 {
		return normalizeNullSet(refSet), normalizeNullInt64(refCode)
	}
	return stringSetFromAPI(ctx, values, types.SetNull(types.StringType), diags), int64FromPtr(code)
}

func uriRulesFromAPI(ctx context.Context, api *apiFilterRegexRules, ref *CDNFilterURIRulesModel, diags *diag.Diagnostics) *CDNFilterURIRulesModel {
	var refAllow, refDeny types.List
	var refCode types.Int64
	if ref != nil {
		refAllow, refCode, refDeny = ref.Allow, ref.AllowStatusCode, ref.Deny
	}
	rules, ok := regexRulesFromAPI(ctx, api, ref != nil, refAllow, refCode, refDeny, false, diags)
	if !ok {
		return ref
	}
	if rules == nil {
		return nil
	}
	return &CDNFilterURIRulesModel{Allow: rules.allow, AllowStatusCode: rules.allowCode, Deny: rules.deny}
}

type blockFlag func(*apiFilterRegexRules) *bool

func blockWithoutUA(r *apiFilterRegexRules) *bool      { return r.BlockWithoutUserAgent }
func blockWithoutReferer(r *apiFilterRegexRules) *bool { return r.BlockWithoutReferer }

func headerRulesFromAPI(ctx context.Context, api *apiFilterRegexRules, flag blockFlag, ref *CDNFilterHeaderRulesModel, diags *diag.Diagnostics) *CDNFilterHeaderRulesModel {
	var refAllow, refDeny types.List
	var refCode types.Int64
	refBlock := false
	if ref != nil {
		refAllow, refCode, refDeny = ref.Allow, ref.AllowStatusCode, ref.Deny
		refBlock = ref.BlockEmpty.ValueBool()
	}
	apiBlock := false
	if api != nil {
		if b := flag(api); b != nil {
			apiBlock = *b
		}
	}
	rules, ok := regexRulesFromAPI(ctx, api, ref != nil, refAllow, refCode, refDeny, apiBlock || refBlock, diags)
	if !ok {
		return ref
	}
	if rules == nil {
		return nil
	}
	return &CDNFilterHeaderRulesModel{Allow: rules.allow, AllowStatusCode: rules.allowCode, Deny: rules.deny, BlockEmpty: types.BoolValue(apiBlock)}
}

type regexRulesState struct {
	allow     types.List
	allowCode types.Int64
	deny      types.List
}

// regexRulesFromAPI holds the logic shared by uri, user_agent and referer.
// It returns ok=false when ref should be kept as is (no rules on either side),
// and nil rules when the API section is null.
func regexRulesFromAPI(ctx context.Context, api *apiFilterRegexRules, hasRef bool, refAllow types.List, refCode types.Int64, refDeny types.List, hasBlock bool, diags *diag.Diagnostics) (*regexRulesState, bool) {
	apiEmpty := api == nil || (len(api.Allow) == 0 && len(api.Deny) == 0)
	refEmpty := len(refAllow.Elements()) == 0 && len(refDeny.Elements()) == 0
	if apiEmpty && refEmpty && !hasBlock {
		return nil, false
	}
	if api == nil {
		return nil, true
	}
	if !hasRef {
		refAllow = types.ListNull(types.StringType)
		refDeny = types.ListNull(types.ObjectType{AttrTypes: filterDenyRegexAttrTypes})
	}

	var out regexRulesState

	allow := make([]string, len(api.Allow))
	for i, a := range api.Allow {
		allow[i] = a.Regex
	}
	var refAllowStrs []string
	if !IsNullOrUnknown(refAllow) {
		refAllow.ElementsAs(ctx, &refAllowStrs, false)
	}
	if len(allow) == 0 && len(refAllowStrs) == 0 {
		out.allow, out.allowCode = normalizeNullList(refAllow, types.StringType), normalizeNullInt64(refCode)
	} else {
		allow = reorderByPlanOrder(refAllowStrs, allow, func(s *string) string { return *s })
		if len(allow) == 0 {
			out.allow = types.ListNull(types.StringType)
		} else {
			l, d := types.ListValueFrom(ctx, types.StringType, allow)
			diags.Append(d...)
			out.allow = l
		}
		out.allowCode = int64FromPtr(api.AllowRuleBlockingHTTPStatusCode)
	}

	denyType := types.ObjectType{AttrTypes: filterDenyRegexAttrTypes}
	deny := make([]CDNFilterDenyRegexModel, len(api.Deny))
	for i, d := range api.Deny {
		deny[i] = CDNFilterDenyRegexModel{Regex: types.StringValue(d.Regex), StatusCode: types.Int64Value(d.HTTPStatusCode)}
	}
	var refDenyModels []CDNFilterDenyRegexModel
	if !IsNullOrUnknown(refDeny) {
		refDeny.ElementsAs(ctx, &refDenyModels, false)
	}
	if len(deny) == 0 && len(refDenyModels) == 0 {
		out.deny = normalizeNullList(refDeny, denyType)
	} else {
		if len(deny) == 0 {
			out.deny = types.ListNull(denyType)
		} else {
			l, d := types.ListValueFrom(ctx, denyType, deny)
			diags.Append(d...)
			out.deny = l
		}
	}
	return &out, true
}

func int64FromPtr(p *int64) types.Int64 {
	if p == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*p)
}

// normalizeNull* turn zero-value (typeless) and unknown values into typed nulls,
// so that values taken from ref are always valid for the schema.
func normalizeNullSet(s types.Set) types.Set {
	if s.IsUnknown() || s.ElementType(context.Background()) == nil {
		return types.SetNull(types.StringType)
	}
	return s
}

func normalizeNullList(l types.List, elem attr.Type) types.List {
	if l.IsUnknown() || l.ElementType(context.Background()) == nil {
		return types.ListNull(elem)
	}
	return l
}

func normalizeNullInt64(v types.Int64) types.Int64 {
	if v.IsUnknown() {
		return types.Int64Null()
	}
	return v
}

// ---------------------------------------------------------------------------
// types.Object helpers
// ---------------------------------------------------------------------------

// accessFilterObjectToModel extracts the model from a known access_filter
// object; it returns nil for null or unknown values.
func accessFilterObjectToModel(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *CDNAccessFilterModel {
	if IsNullOrUnknown(obj) {
		return nil
	}
	var m CDNAccessFilterModel
	diags.Append(obj.As(ctx, &m, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}
	return &m
}

func accessFilterModelToObject(ctx context.Context, m CDNAccessFilterModel, diags *diag.Diagnostics) types.Object {
	obj, d := types.ObjectValueFrom(ctx, accessFilterAttrTypes, m)
	diags.Append(d...)
	return obj
}
