---
page_title: "Guide: Importing existing resources into Terraform"
description: |-
  How to bring existing Qrator domains, services, certificates, and CDN configurations under Terraform management without recreating them.
---

# Importing existing resources into Terraform

If you already have domains, services, and certificates configured in Qrator and want to start managing them through this Terraform provider, use `terraform import`. Nothing is recreated — import reads the current state from the API and records it in the Terraform state file.

## General workflow

For every existing resource:

1. Write a matching `resource "..." "..."` block in your `.tf` files
2. Run `terraform import <resource_address> <id>`
3. Run `terraform plan` — it will show any differences between what you wrote and what the API has
4. Adjust your `.tf` files to match, then run `terraform apply` to sync

~> **Note:** After import, `terraform plan` will always show a diff for `client_id` (and for `qrator_service` — also `ips`) because these are not readable from the API after the fact. Fill them in from your known values and apply once to sync state.

---

## Import reference

### `qrator_domain`

```shell
terraform import qrator_domain.example <domain_id>
```

Minimum `.tf` block needed before import:

```terraform
resource "qrator_domain" "example" {
  client_id = var.client_id   # fill in your actual client_id
  name      = "example.com"   # fill in the actual domain name
}
```

After import, `terraform plan` will show diffs for `client_id` and `name`. Apply to sync.

---

### `qrator_domain_services`

```shell
terraform import qrator_domain_services.example <domain_id>
```

```terraform
resource "qrator_domain_services" "example" {
  domain_id = <domain_id>
  # leave service lists empty — they will be populated from the API after import
}
```

After import, `terraform plan` shows the full current service configuration read from the API. Copy it into your `.tf` file.

---

### `qrator_domain_sni`

```shell
terraform import qrator_domain_sni.example <domain_id>
```

```terraform
resource "qrator_domain_sni" "example" {
  domain_id = <domain_id>
  links     = []
}
```

---

### `qrator_domain_whitelist` / `qrator_domain_blacklist`

```shell
terraform import qrator_domain_whitelist.example <domain_id>
terraform import qrator_domain_blacklist.example <domain_id>
```

```terraform
resource "qrator_domain_whitelist" "example" {
  domain_id = <domain_id>
  entries   = []
}

resource "qrator_domain_blacklist" "example" {
  domain_id = <domain_id>
  entries   = []
}
```

---

### `qrator_service`

```shell
terraform import qrator_service.example <service_id>
```

```terraform
resource "qrator_service" "example" {
  client_id = var.client_id   # fill in your actual client_id
  name      = "my-service"    # fill in the actual service name
  ips       = ["192.0.2.1"]   # fill in the actual upstream IPs
}
```

After import, `terraform plan` will show diffs for `client_id`, `name`, and `ips`. Apply to sync.

---

### `qrator_service_services`

```shell
terraform import qrator_service_services.example <service_id>
```

```terraform
resource "qrator_service_services" "example" {
  service_id = <service_id>
}
```

---

### `qrator_service_sni`

```shell
terraform import qrator_service_sni.example <service_id>
```

```terraform
resource "qrator_service_sni" "example" {
  service_id = <service_id>
  links      = []
}
```

---

### `qrator_service_whitelist` / `qrator_service_blacklist`

```shell
terraform import qrator_service_whitelist.example <service_id>
terraform import qrator_service_blacklist.example <service_id>
```

```terraform
resource "qrator_service_whitelist" "example" {
  service_id = <service_id>
  entries    = []
}

resource "qrator_service_blacklist" "example" {
  service_id = <service_id>
  entries    = []
}
```

---

### `qrator_cdn`

```shell
terraform import qrator_cdn.example <domain_id>
```

```terraform
resource "qrator_cdn" "example" {
  domain_id = <domain_id>
}
```

---

### `qrator_cdn_sni`

```shell
terraform import qrator_cdn_sni.example <domain_id>
```

```terraform
resource "qrator_cdn_sni" "example" {
  domain_id = <domain_id>
  links     = []
}
```

---

### `qrator_client_certificate`

```shell
terraform import qrator_client_certificate.example <client_id>/<certificate_id>
```

```terraform
resource "qrator_client_certificate" "example" {
  client_id = var.client_id
  type      = "upload"   # or "letsencrypt"
}
```

~> **Note:** Sensitive fields (`cert`, `key`) are write-only and will not be populated after import. If they are present in your `.tf` configuration, subsequent plans may show a diff — this is expected. The actual certificate content on the server is not affected.

---

## Importing a full setup at once

For an existing domain with all its associated resources, run all imports in sequence:

```shell
# 1. Domain
terraform import qrator_domain.example 11111

# 2. Domain configuration
terraform import qrator_domain_services.example 11111
terraform import qrator_domain_sni.example 11111
terraform import qrator_domain_whitelist.example 11111
terraform import qrator_domain_blacklist.example 11111

# 3. CDN (if applicable)
terraform import qrator_cdn.example 11111
terraform import qrator_cdn_sni.example 11111

# 4. Service
terraform import qrator_service.example 22222

# 5. Service configuration
terraform import qrator_service_services.example 22222
terraform import qrator_service_sni.example 22222
terraform import qrator_service_whitelist.example 22222
terraform import qrator_service_blacklist.example 22222

# 6. Certificate
terraform import qrator_client_certificate.example 33333/44444
```

Then:

```shell
terraform plan
```

Review the diffs, update your `.tf` files to match the current configuration, and run `terraform apply` to achieve a clean state with no outstanding diffs.
