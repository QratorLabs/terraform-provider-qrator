package provider

import "fmt"

// entityKind distinguishes between "domain" and "service" entities.
// Both share the same sub-resources (whitelist, blacklist, SNI, name, policy)
// but differ in API path and schema field naming.
type entityKind string

const (
	entityDomain  entityKind = "domain"
	entityService entityKind = "service"
)

// apiPath returns the API request path for the given entity ID.
func (e entityKind) apiPath(id int64) string {
	return fmt.Sprintf("/request/%s/%d", e, id)
}

// idField returns the schema attribute name for the entity ID
// (e.g. "domain_id" or "service_id").
func (e entityKind) idField() string {
	return string(e) + "_id"
}

// String returns the entity kind as a string.
func (e entityKind) String() string {
	return string(e)
}

// clientPath returns the API path for client-level operations.
func (e entityKind) clientPath(clientID int64) string {
	return fmt.Sprintf("/request/client/%d", clientID)
}

// createMethod returns the API method name for creating an entity.
func (e entityKind) createMethod() string {
	return string(e) + "_create"
}

// createParams builds the params array for the create API call.
// domain_create: [upstream_list, name] — upstream_list is always empty.
// service_create: [ip_list, service_list, name] — service_list is always empty.
func (e entityKind) createParams(name string, ips []string) interface{} {
	if e == entityService {
		return []interface{}{ips, []interface{}{}, name}
	}
	return []interface{}{[]interface{}{}, name}
}
