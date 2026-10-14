---
page_title: "Upgrade Guide: v0.4 → v0.5"
description: |-
  Breaking changes in provider version 0.5 (CDN access filter, content compression) and steps to upgrade your Terraform configuration.
---

# Upgrading from v0.4 to v0.5

Qrator API v1.5.21 changes several CDN settings. Provider v0.5 follows these changes in `qrator_cdn`:

1. **Access filter** — `blocked_uri` and `white_uri` are removed; the new `access_filter` attribute manages the whole CDN access filter: client IP, country, HTTP method, URL, `User-Agent` and `Referer` rules.
2. **Content compression** — `compress_disabled` is removed; the new `content_compression` attribute sets the MIME types compressed with each algorithm.
3. **`client_no_cache` is removed** — the option is no longer supported by the Qrator API.

Provider v0.4 does not work with API v1.5.21: `terraform plan` fails for `qrator_cdn` resources. Upgrade the provider when the new API is released.

The provider migrates your state automatically. **You only need to update `.tf` files that use `blocked_uri`, `white_uri`, `compress_disabled` or `client_no_cache`.**

---

## 1. Access filter replaces `blocked_uri` and `white_uri`

### What changed

| v0.4 | v0.5 |
|------|------|
| `blocked_uri = [{ uri = "...", code = N }]` | `access_filter.uri.deny = [{ regex = "...", status_code = N }]` |
| `white_uri = ["..."]` (non-matching requests got `404`) | `access_filter.uri.allow = ["..."]` with `access_filter.uri.allow_status_code = 404` |

**Old (v0.4):**

```hcl
resource "qrator_cdn" "example" {
  domain_id = 12345

  blocked_uri = [
    { uri = "/admin/.*", code = 404 },
  ]
  white_uri = ["/api/.*", "/static/.*"]
}
```

**New (v0.5):**

```hcl
resource "qrator_cdn" "example" {
  domain_id = 12345

  access_filter = {
    uri = {
      deny              = [{ regex = "/admin/.*", status_code = 404 }]
      allow             = ["/api/.*", "/static/.*"]
      allow_status_code = 404
    }
  }
}
```

#### Keep `allow_status_code = 404`

The CDN used to answer `404` to requests that matched none of the `white_uri` patterns. The API migration keeps this behaviour by storing `404` for migrated rules. If you omit `allow_status_code`, `terraform apply` clears it and the CDN starts answering **`403`** (the default) instead.

#### Order of `deny` entries

Regex deny entries are checked in the listed order and the first matching entry determines the response code. The migrated `uri.deny` keeps the order of `blocked_uri`; keep the same order in the configuration.

#### `access_filter` manages the whole filter

When `access_filter` is set, every section that is not described in it is cleared on `terraform apply`, including rules added in the Qrator dashboard. Describe the complete filter in `access_filter`, or omit the attribute to manage the filter in the dashboard. See the [`qrator_cdn` documentation](../resources/cdn.md#access-filter) for all sections and value formats.

### What happens if you don't update the config

`terraform plan` fails with a parse error and nothing is changed:

```
Error: Unsupported argument
An argument named "blocked_uri" is not expected here.
```

### State migration

On the first `terraform plan` with v0.5 the provider upgrades the `qrator_cdn` state:

- `blocked_uri` entries become `access_filter.uri.deny`;
- `white_uri` entries become `access_filter.uri.allow` with `allow_status_code = 404`;
- resources that had neither keep `access_filter` unset.

If you rewrite the configuration as shown above, the plan shows no changes.

If you remove `blocked_uri` and `white_uri` without adding `access_filter`, the plan shows `access_filter` being removed. This only stops Terraform from managing the filter: `terraform apply` does not call the API and the rules stay in Qrator.

---

## 2. `content_compression` replaces `compress_disabled`

### What changed

`compress_disabled` (a list of disabled algorithms) is deprecated by the Qrator API and removed from the provider. The new `content_compression` attribute lists, for each algorithm, the MIME types CDN compresses with it. All four algorithms (`gzip`, `br`, `deflate`, `zstd`) must be listed:

- `["*"]` — any MIME type (the Qrator default);
- `[]` — the algorithm is disabled;
- a list of MIME types, e.g. `["text/html", "application/json"]` — only these types.

### Migration

| v0.4 | v0.5 |
|------|------|
| `compress_disabled` omitted or `[]` | omit `content_compression` |
| `compress_disabled = ["br"]` | `content_compression = { gzip = ["*"], br = [], deflate = ["*"], zstd = ["*"] }` |
| `compress_disabled = ["gzip", "deflate"]` | `content_compression = { gzip = [], br = ["*"], deflate = [], zstd = ["*"] }` |

If `compress_disabled` is left in the configuration, `terraform plan` fails:

```
Error: Unsupported argument
An argument named "compress_disabled" is not expected here.
```

### State migration

On the first `terraform plan` with v0.5 a non-empty `compress_disabled` becomes `content_compression`: the listed algorithms get `[]`, the others `["*"]`. If you rewrite the configuration as shown in the table, the plan shows no changes.

An empty `compress_disabled` leaves `content_compression` unset. When `content_compression` is omitted, Terraform does not manage the setting: it is neither read nor changed. If you remove a non-empty `compress_disabled` without adding `content_compression`, the plan shows `content_compression` being removed; this only stops Terraform from managing it, and `terraform apply` does not call the API.

---

## 3. `client_no_cache` removed

The option is no longer supported by the Qrator API. Remove `client_no_cache` from your `qrator_cdn` resources, otherwise `terraform plan` fails:

```
Error: Unsupported argument
An argument named "client_no_cache" is not expected here.
```

The attribute is dropped from the state automatically.

---

## Upgrade steps

1. **Update the provider version** in your `terraform` block and run `terraform init -upgrade`:

   ```hcl
   terraform {
     required_providers {
       qrator = {
         source  = "qratorlabs/qrator"
         version = "~> 0.5"
       }
     }
   }
   ```

2. **Update `qrator_cdn` resources**:
   - replace `blocked_uri` and `white_uri` with `access_filter.uri`, keeping `allow_status_code = 404` for former `white_uri` rules;
   - remove `client_no_cache`;
   - replace `compress_disabled` with `content_compression`.

3. **Run `terraform plan`.** The state is migrated automatically and no changes are expected.
