---
page_title: "Provider: Qrator"
description: |-
  The Qrator provider manages domains, services, SNI, whitelist/blacklist, CDN configurations, and client certificates in Qrator.
---

# Qrator Provider

The Qrator provider allows you to manage domains, services, SNI, whitelist/blacklist, CDN configurations, and client certificates in [Qrator](https://qrator.net/).

## Authentication

The provider requires an API key and endpoint URL. These can be set via provider configuration or environment variables.

## Example Usage

```terraform
terraform {
  required_providers {
    qrator = {
      source = "qratorlabs/qrator"
    }
  }
}

provider "qrator" {
  api_key  = var.qrator_api_key
  endpoint = "https://api.qrator.net"
}
```

## Resources

| Resource | Description |
|----------|-------------|
| `qrator_domain` | Domain name management |
| `qrator_domain_services` | Service list (HTTP, NAT, NAT-all, TCP proxy, WebSocket) |
| `qrator_domain_sni` | SNI hostname-to-certificate mappings |
| `qrator_domain_whitelist` | IP whitelist (allowed addresses) |
| `qrator_domain_blacklist` | IP blacklist (blocked addresses) |
| `qrator_cdn` | CDN configuration |
| `qrator_client_certificate` | Client certificates (upload / Let's Encrypt) |

## Schema

### Required

- `api_key` (String, Sensitive) The API key for authenticating requests to the Qrator API. Can also be set via the `QRATOR_API_KEY` environment variable.
- `endpoint` (String) The base URL of the Qrator API (e.g., `https://api.qrator.net`). Can also be set via the `QRATOR_ENDPOINT` environment variable.
