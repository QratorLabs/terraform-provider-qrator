# Terraform Provider for Qrator

Terraform provider for managing [Qrator](https://qrator.net/) CDN and certificate resources.

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
      version = "~> 0.1"
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

- `qrator_cdn` — Manages CDN configuration for a domain (caching, headers, SNI).
- `qrator_client_certificate` — Manages client TLS certificates (upload or Let's Encrypt).

## Example

```terraform
resource "qrator_cdn" "example" {
  domain_id     = 12345
  cache_control = true
}

resource "qrator_client_certificate" "cert" {
  client_id = 67890
  type      = "upload"
  certificates = [
    {
      cert = file("cert.pem")
      key  = file("key.pem")
    }
  ]
}
```

## Development

```shell
go build -o terraform-provider-qrator .
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
