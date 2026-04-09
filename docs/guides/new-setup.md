---
page_title: "Guide: Creating a new domain or service from scratch"
description: |-
  Step-by-step guide for setting up a new domain or service in Qrator using Terraform, including domain moderation.
---

# Creating a new domain or service from scratch

This guide covers the full lifecycle of creating a new Qrator domain (or service) from scratch using Terraform — from initial resource creation through the domain moderation period to full production configuration.

## Prerequisites

- Qrator API key and your `client_id`
- Terraform ≥ 1.0

## Provider setup

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

variable "qrator_api_key" {
  type      = string
  sensitive = true
}

variable "client_id" {
  type = number
}
```

---

## Scenario A: New domain

### Step 1 — Create the domain

Start with the minimum: just the domain resource. Do not configure services, SNI, or whitelist yet — the domain goes through a moderation process before it becomes active.

```terraform
resource "qrator_domain" "example" {
  client_id = var.client_id
  name      = "example.com"
}
```

```shell
terraform apply
```

Terraform creates the domain and stores its `id` in state. The domain is now **pending moderation** on the Qrator side.

### Step 2 — Wait for moderation approval

During moderation, Qrator verifies the domain. This is an out-of-band process — you do not need to do anything in Terraform. You can check the moderation status in the Qrator dashboard or via the support channel.

~> **Note:** Some API operations on the domain (services, SNI) may be unavailable until moderation completes. Do not run `terraform apply` for dependent resources until the domain is approved.

### Step 3 — Configure services, SNI, and IP lists

Once the domain is approved, add the remaining resources. All of them reference the domain via `qrator_domain.example.id` — Terraform knows the ID from step 1.

```terraform
# HTTP/HTTPS service on the domain
resource "qrator_domain_services" "example" {
  domain_id = qrator_domain.example.id

  http = [
    {
      port              = 80
      upstream_balancer = "roundrobin"
      upstream_weights  = false
      upstream_backups  = false
      upstreams = [
        { ip = "10.0.0.1", port = 8080, weight = 100, type = "primary" },
      ]
    },
    {
      port              = 443
      ssl               = true
      http2             = true
      upstream_balancer = "roundrobin"
      upstream_weights  = false
      upstream_backups  = false
      upstream_ssl      = true
      upstreams = [
        { ip = "10.0.0.1", port = 8443, weight = 100, type = "primary" },
      ]
    },
  ]
}

# Let's Encrypt certificate for SNI
resource "qrator_client_certificate" "example" {
  client_id = var.client_id
  type      = "letsencrypt"
  domain_id = qrator_domain.example.id
  hostnames = ["example.com", "www.example.com"]
}

# SNI bindings
resource "qrator_domain_sni" "example" {
  domain_id = qrator_domain.example.id

  links = [
    {
      certificate = qrator_client_certificate.example.id
    },
  ]
}

# Whitelist with default drop (optional — only if access restriction is needed)
resource "qrator_domain_whitelist" "example" {
  domain_id    = qrator_domain.example.id
  default_drop = false

  entries = []
}
```

```shell
terraform apply
```

### Step 4 (optional) — Enable CDN

If CDN is enabled for your domain, configure it after the domain is fully set up. The `default_host` attribute is read-only and returns the CDN hostname assigned by Qrator — use it to set up your DNS CNAME.

```terraform
resource "qrator_cdn" "example" {
  domain_id     = qrator_domain.example.id
  cache_control = "cdn"
}

output "cdn_default_host" {
  description = "CDN hostname to use as DNS CNAME target."
  value       = qrator_cdn.example.default_host
}
```

```shell
terraform apply
```

---

## Scenario B: New service (L3/L4)

Services do not require moderation and become active immediately after `status_set("online")`.

### Step 1 — Create the service

```terraform
resource "qrator_service" "example" {
  client_id = var.client_id
  name      = "my-service"
  ips       = ["192.0.2.1", "198.51.100.12"]
  # status defaults to "online"
}
```

```shell
terraform apply
```

The service is created and activated. You can now configure all dependent resources.

### Step 2 — Configure service entries, SNI, and IP lists

```terraform
resource "qrator_service_services" "example" {
  service_id = qrator_service.example.id

  dns = [{ port = 53 }]

  http = [
    {
      port = 443
      ssl  = true
      upstream = {
        ssl = true
      }
    },
  ]

  icmp = [{ rate_limit = 80000 }]
}

resource "qrator_service_whitelist" "example" {
  service_id = qrator_service.example.id
  entries    = []
}
```

```shell
terraform apply
```

---

---

## Maintenance mode

Both domains and services support a maintenance mode that applies softer filtering and ignores application errors for a defined time window. It is useful during planned deployments or configuration changes.

Set `maintenance_until` to a Unix timestamp to enable maintenance mode, or omit / set to `null` to disable it:

```terraform
resource "qrator_domain" "example" {
  client_id         = var.client_id
  name              = "example.com"
  maintenance_until = 1775520000 # enable until 2026-04-07T00:00:00Z
}
```

```terraform
resource "qrator_service" "example" {
  client_id         = var.client_id
  name              = "my-service"
  ips               = ["192.0.2.1"]
  maintenance_until = 1775520000
}
```

To disable maintenance mode, remove the attribute or set it explicitly to `null`:

```terraform
resource "qrator_domain" "example" {
  client_id         = var.client_id
  name              = "example.com"
  maintenance_until = null
}
```

---

## Dependency order

Terraform resolves dependencies automatically via references (`qrator_domain.example.id`, etc.). The recommended resource creation order for a domain is:

1. `qrator_client_certificate` (if uploading a cert — it can be created before the domain)
2. `qrator_domain`
3. *(wait for moderation)*
4. `qrator_domain_services`
5. `qrator_domain_sni`
6. `qrator_domain_whitelist` / `qrator_domain_blacklist`
7. `qrator_cdn` / `qrator_cdn_sni` (if CDN is enabled)
