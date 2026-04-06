package provider

import (
	"reflect"
	"testing"
)

func TestEntityKindAPIPath(t *testing.T) {
	tests := []struct {
		entity entityKind
		id     int64
		want   string
	}{
		{entityDomain, 123, "/request/domain/123"},
		{entityService, 456, "/request/service/456"},
		{entityDomain, 0, "/request/domain/0"},
	}
	for _, tt := range tests {
		got := tt.entity.apiPath(tt.id)
		if got != tt.want {
			t.Errorf("apiPath(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestEntityKindIDField(t *testing.T) {
	if got := entityDomain.idField(); got != "domain_id" {
		t.Errorf("domain.idField() = %q, want %q", got, "domain_id")
	}
	if got := entityService.idField(); got != "service_id" {
		t.Errorf("service.idField() = %q, want %q", got, "service_id")
	}
}

func TestEntityKindString(t *testing.T) {
	if got := entityDomain.String(); got != "domain" {
		t.Errorf("domain.String() = %q, want %q", got, "domain")
	}
	if got := entityService.String(); got != "service" {
		t.Errorf("service.String() = %q, want %q", got, "service")
	}
}

func TestEntityKindClientPath(t *testing.T) {
	tests := []struct {
		entity   entityKind
		clientID int64
		want     string
	}{
		{entityDomain, 42, "/request/client/42"},
		{entityService, 99, "/request/client/99"},
	}
	for _, tt := range tests {
		got := tt.entity.clientPath(tt.clientID)
		if got != tt.want {
			t.Errorf("clientPath(%d) = %q, want %q", tt.clientID, got, tt.want)
		}
	}
}

func TestEntityKindCreateMethod(t *testing.T) {
	if got := entityDomain.createMethod(); got != "domain_create" {
		t.Errorf("domain.createMethod() = %q, want %q", got, "domain_create")
	}
	if got := entityService.createMethod(); got != "service_create" {
		t.Errorf("service.createMethod() = %q, want %q", got, "service_create")
	}
}

func TestEntityKindCreateParams(t *testing.T) {
	t.Run("domain has no ips param", func(t *testing.T) {
		got := entityDomain.createParams("example.com", nil)
		want := []interface{}{[]interface{}{}, "example.com"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("domain.createParams() = %v, want %v", got, want)
		}
	})

	t.Run("service includes ips", func(t *testing.T) {
		ips := []string{"1.2.3.4", "5.6.7.8"}
		got := entityService.createParams("my-service", ips)
		want := []interface{}{ips, []interface{}{}, "my-service"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("service.createParams() = %v, want %v", got, want)
		}
	})

	t.Run("domain ignores provided ips", func(t *testing.T) {
		got := entityDomain.createParams("example.com", []string{"1.2.3.4"})
		want := []interface{}{[]interface{}{}, "example.com"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("domain.createParams() = %v, want %v", got, want)
		}
	})
}
