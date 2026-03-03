terraform {
  required_providers {
    qrator = {
      source = "qratorlabs/qrator"
    }
  }
}

provider "qrator" {
  api_key  = var.api_key
  endpoint = var.endpoint
}

variable "api_key" {
  type      = string
  sensitive = true
}

variable "endpoint" {
  type    = string
  default = "https://api.qrator.net"
}

variable "domain_id" {
  type = number
}

# --- Domain name and access policy ---

resource "qrator_domain" "example" {
  id   = var.domain_id
  name = "example.com"
}

# Restrict access to whitelisted IPs only
resource "qrator_domain" "restricted" {
  id                     = var.domain_id
  name                   = "internal.example.com"
  not_whitelisted_policy = "drop"
}

# --- Domain services ---

resource "qrator_domain_services" "web" {
  domain_id = var.domain_id

  http = [
    {
      port              = 80
      upstream_balancer = "roundrobin"
      upstream_weights  = false
      upstream_backups  = false
      upstream_ssl      = false
      upstreams = [
        { ip = "10.0.0.1", port = 8080, weight = 100, type = "primary" },
      ]
    },
    {
      port              = 443
      ssl               = true
      http2             = true
      upstream_balancer = "roundrobin"
      upstream_weights  = true
      upstream_backups  = false
      upstream_ssl      = true
      upstreams = [
        { ip = "10.0.0.1", port = 8443, weight = 100, type = "primary" },
        { ip = "10.0.0.2", port = 8443, weight = 50, type = "backup" },
      ]
    },
  ]

  nat = [
    {
      port          = 53
      proto         = "udp"
      drop_amp      = true
      upstream_ip   = "10.0.0.2"
      upstream_port = 53
    },
  ]

  tcpproxy = [
    {
      port = 3306
      upstreams = [
        { ip = "10.0.0.4", port = 3306, weight = 100, type = "primary" },
      ]
    },
  ]

  websocket = [
    {
      port         = 8443
      ssl          = true
      upstream_ssl = true
      upstreams = [
        { ip = "10.0.0.5", port = 8443, weight = 100, type = "primary" },
      ]
    },
  ]
}

# --- Domain SNI ---

resource "qrator_domain_sni" "example" {
  domain_id = var.domain_id

  links = [
    {
      certificate = qrator_client_certificate.cert.id
    },
    {
      host        = "example.com"
      certificate = qrator_client_certificate.cert.id
    },
  ]
}

# --- Domain whitelist / blacklist ---

resource "qrator_domain_whitelist" "example" {
  domain_id = var.domain_id

  entries = [
    {
      ip      = "203.0.113.10"
      comment = "Office gateway"
    },
    {
      ip      = "198.51.100.1"
      ttl     = 3600
      comment = "Temporary access"
    },
  ]
}

resource "qrator_domain_blacklist" "example" {
  domain_id = var.domain_id

  entries = [
    {
      ip      = "192.0.2.100"
      comment = "Known attacker"
    },
  ]
}

# --- Certificate (referenced by SNI) ---

resource "qrator_client_certificate" "cert" {
  client_id = 67890
  type      = "letsencrypt"
  domain_id = var.domain_id
  hostnames = ["example.com", "www.example.com"]
}
