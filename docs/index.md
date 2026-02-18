---
page_title: "Provider: Qrator"
description: |-
  The Qrator provider manages CDN configurations and client certificates in Qrator.
---

# Qrator Provider

The Qrator provider allows you to manage CDN configurations and client certificates in [Qrator](https://qrator.net/).

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

resource "qrator_cdn" "example" {
  domain_id     = 12345
  cache_control = true
}
```

## Schema

### Required

- `api_key` (String, Sensitive) The API key for authenticating requests to the Qrator API. Can also be set via the `QRATOR_API_KEY` environment variable.
- `endpoint` (String) The base URL of the Qrator API (e.g., `https://api.qrator.net`). Can also be set via the `QRATOR_ENDPOINT` environment variable.
