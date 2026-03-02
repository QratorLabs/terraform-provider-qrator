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
