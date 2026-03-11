# Terraform Provider for Qrator

Terraform provider for managing [Qrator](https://qrator.net/) domains, services, CDN configurations, and client certificates.

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.24 (to build the provider plugin)

## Installation

This provider is published on the [Terraform Registry](https://registry.terraform.io/providers/qratorlabs/qrator/latest).

```terraform
terraform {
  required_providers {
    qrator = {
      source  = "qratorlabs/qrator"
      version = "~> 0.2"
    }
  }
}
```

## Authentication

The provider requires an API key for authentication:

```terraform
provider "qrator" {
  api_key  = var.api_key
  endpoint = "https://api.qrator.net"
}
```

Or via environment variables:

```shell
export QRATOR_API_KEY="your-api-key"
export QRATOR_ENDPOINT="https://api.qrator.net"
```

## Resources

### Domain

| Resource | Description |
|----------|-------------|
| `qrator_domain` | Domain management (name, policy) |
| `qrator_domain_services` | Domain service list (HTTP, NAT, NAT-all, TCP proxy, WebSocket) |
| `qrator_domain_sni` | Domain SNI hostname-to-certificate mappings |
| `qrator_domain_whitelist` | Domain IP whitelist (allowed addresses) |
| `qrator_domain_blacklist` | Domain IP blacklist (blocked addresses) |

### Service

| Resource | Description |
|----------|-------------|
| `qrator_service` | Service management (name, policy, status, upstream IPs) |
| `qrator_service_services` | Service list (DNS, HTTP, ICMP, NAT, ingress/egress types) |
| `qrator_service_sni` | Service SNI hostname-to-certificate mappings |
| `qrator_service_whitelist` | Service IP whitelist (allowed addresses) |
| `qrator_service_blacklist` | Service IP blacklist (blocked addresses) |

### CDN & Certificates

| Resource | Description |
|----------|-------------|
| `qrator_cdn` | CDN configuration (caching, headers, compression) |
| `qrator_cdn_sni` | CDN SNI hostname-to-certificate mappings |
| `qrator_client_certificate` | Client TLS certificates (upload or Let's Encrypt) |

## Examples

See the [`examples/`](examples/) directory for complete configurations.

## Development

```shell
go build -o terraform-provider-qrator .
```

Run tests:

```shell
go test ./... -v -count=1
```

To use a local build, add to `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "qratorlabs/qrator" = "/path/to/build/directory"
  }
  direct {}
}
```

## License

MPL-2.0. See [LICENSE](LICENSE).
