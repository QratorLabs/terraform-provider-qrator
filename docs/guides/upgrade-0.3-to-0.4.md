---
page_title: "Upgrade Guide: v0.3 → v0.4"
description: |-
  Breaking changes in provider version 0.4 and steps to upgrade your Terraform configuration.
---

# Upgrading from v0.3 to v0.4

Version 0.4 includes two breaking changes that require updating your Terraform configuration files:

1. **IP list resources** — `entries` attribute changed from a list of objects to a map keyed by IP address.
2. **CDN resource** — `cache_ignore_params` replaced by `cache_query_params`.

In both cases the provider automatically migrates your state file on the first `terraform plan` with the new binary. **You only need to update your `.tf` configuration files.**

---

## 1. IP list entries format change

Affects: `qrator_domain_whitelist`, `qrator_domain_blacklist`, `qrator_service_whitelist`, `qrator_service_blacklist`.

### What changed

The `entries` attribute was a list where each element contained an `ip` field:

```hcl
# v0.3 — list syntax
entries = [
  { ip = "203.0.113.10", comment = "Office gateway" },
  { ip = "198.51.100.1", ttl = 3600 },
]
```

In v0.4 `entries` is a map. The IP address becomes the map key and there is no `ip` field inside the value:

```hcl
# v0.4 — map syntax
entries = {
  "203.0.113.10" = { comment = "Office gateway" }
  "198.51.100.1" = { ttl = 3600 }
}
```

If an IP has neither a comment nor a TTL (both defaults), write an empty value object:

```hcl
entries = {
  "10.0.0.1" = {}
}
```

### What happens if you don't update the config

Running `terraform plan` with an outdated config that still uses the list syntax produces a clear parse error:

```
Error: Unsupported argument / An argument named "ip" is not expected here.
```

No state is modified and nothing is applied. Update the `.tf` file and re-run.

### State migration

The provider automatically migrates the state from the old list format to the new map format on the first `terraform plan`. No manual `terraform state` commands are needed. The migration sets `exclusive = true` for all existing resources, preserving the pre-v0.4 behaviour (see the `exclusive` flag below).

### New `exclusive` attribute

All four IP list resources have a new optional `exclusive` attribute (default: `true`).

- `exclusive = true` (default) — Terraform owns the entire list. Any IP not present in the `entries` map is removed on the next `terraform apply`, including IPs added via the Qrator dashboard or API. This matches the behaviour of the provider before v0.4.
- `exclusive = false` (**additive mode**) — Terraform only manages the IPs it created. IPs added via the Qrator dashboard or API are left untouched.

The migrated state sets `exclusive = true`, which preserves the pre-v0.4 behaviour. If you want to allow externally managed IPs to coexist, set `exclusive = false` explicitly:

```hcl
resource "qrator_domain_whitelist" "example" {
  domain_id = qrator_domain.example.id
  exclusive  = false   # opt in to additive mode

  entries = {
    "203.0.113.10" = { comment = "Office gateway" }
  }
}
```

---

## 2. CDN: `cache_ignore_params` replaced by `cache_query_params`

Affects: `qrator_cdn`.

### What changed

The boolean attribute `cache_ignore_params` has been replaced by a structured `cache_query_params` block that gives fine-grained control over which query parameters are included in the cache key.

**Old (v0.3):**

```hcl
resource "qrator_cdn" "example" {
  domain_id          = qrator_domain.example.id
  cache_ignore_params = false   # boolean: ignore all params or not
}
```

**New (v0.4):**

```hcl
resource "qrator_cdn" "example" {
  domain_id = qrator_domain.example.id

  # Remove cache_ignore_params and add cache_query_params (or omit for default).
  cache_query_params = {
    mode   = "ignore"              # "ignore" or "use"
    params = ["utm_source", "utm_medium"]
  }
}
```

### Attribute reference

| `mode` | `params` | Effect |
|--------|----------|--------|
| `"ignore"` | `[]` (empty) | All query parameters are part of the cache key (equivalent to old `cache_ignore_params = false`). This is the default. |
| `"ignore"` | `["utm_source", "utm_medium"]` | All params except `utm_source` and `utm_medium` are in the cache key. |
| `"use"` | `["page", "lang"]` | Only `page` and `lang` are part of the cache key; all others are ignored. |
| `"use"` | `[]` (empty) | All query parameters are ignored when caching (equivalent to old `cache_ignore_params = true`). |

### Equivalences for migration

| Old config | New config |
|------------|------------|
| `cache_ignore_params = false` or omitted | Omit `cache_query_params` entirely (default applies), or `cache_query_params = { mode = "ignore", params = [] }` |
| `cache_ignore_params = true` | `cache_query_params = { mode = "use", params = [] }` |

### State migration

The provider automatically upgrades the CDN state on the first `terraform plan`:

- `cache_ignore_params = false` → `cache_query_params = { mode = "ignore", params = [] }`
- `cache_ignore_params = true` → `cache_query_params = { mode = "use", params = [] }`

After the state is migrated you still need to remove `cache_ignore_params` from your `.tf` files — it is no longer a valid attribute and Terraform will error if it remains:

```
Error: Unsupported argument
An argument named "cache_ignore_params" is not expected here.
```

---

## Upgrade steps

1. **Update the provider version** in your `terraform` block:

   ```hcl
   terraform {
     required_providers {
       qrator = {
         source  = "qratorlabs/qrator"
         version = "~> 0.4"
       }
     }
   }
   ```

   Run `terraform init -upgrade` to download the new binary.

2. **Update IP list resources** — convert `entries = [...]` to `entries = { ... }` in all four IP list resources.

3. **Update CDN resources** — remove `cache_ignore_params` and add `cache_query_params` if you need non-default behaviour; otherwise omit the attribute.

4. **Run `terraform plan`** — the provider migrates state automatically. Review the plan output. No unexpected changes should appear.

5. **Run `terraform apply`** if the plan shows changes you want to apply (e.g. to push updated `cache_query_params` settings to the API).
