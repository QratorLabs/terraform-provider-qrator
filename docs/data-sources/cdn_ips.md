---
page_title: "qrator_cdn_ips Data Source - terraform-provider-qrator"
subcategory: ""
description: |-
  Returns the list of IP addresses of CDN caching servers. Useful for whitelisting CDN servers on the origin side.
---

# qrator_cdn_ips (Data Source)

Returns the list of IP addresses of CDN caching servers for a given CDN domain.

## Example Usage

```terraform
data "qrator_cdn_ips" "ru" {
  domain_id = 12345
  region    = "ru"
}

data "qrator_cdn_ips" "default" {
  domain_id = 12345
}
```

## See Also

- [qrator_cdn](../resources/cdn.md) — CDN configuration resource.

## Schema

### Required

- `domain_id` (Number) The ID of the CDN domain.

### Optional

- `region` (String) CDN region to query. Allowed values: `"ru"`, `"global"`. Omit to use the default region.

### Read-Only

- `ips` (List of String) List of IP addresses of CDN caching servers.
