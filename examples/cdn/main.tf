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

variable "client_id" {
  type = number
}

# --- CDN configuration ---

resource "qrator_cdn" "example" {
  domain_id     = var.domain_id
  cache_control = "cdn"
  http2         = true

  access_control_allow_origin = ["https://(www\\.)?example\\.com"]

  cache_ignore_params = false
  client_no_cache     = false
  redirect_code       = 301

  client_headers   = ["X-Custom-Header:value"]
  client_ip_header = "X-Real-IP"
  upstream_headers = ["X-CDN-Service:Qrator"]

  compress_disabled = ["br"]

  cache_errors = [
    {
      code    = 502
      timeout = 5000
    },
  ]

  cache_errors_permanent = [
    {
      code    = 429
      timeout = 60000
    },
  ]

  blocked_uri = [
    {
      uri  = "/admin/.*"
      code = 403
    },
  ]

  white_uri = ["/api/.*", "/static/.*"]
}

# --- CDN SNI ---

resource "qrator_cdn_sni" "example" {
  domain_id = var.domain_id

  entries = [
    {
      host        = "example.com"
      certificate = qrator_client_certificate.cert.id
    },
    {
      host        = "cdn.example.com"
      certificate = qrator_client_certificate.cert.id
    },
  ]
}

# --- Client certificates ---

# Upload certificate
resource "qrator_client_certificate" "cert" {
  client_id = var.client_id
  type      = "upload"

  certificates {
    cert = file("cert.pem")
    key  = file("key.pem")
  }
}

# Let's Encrypt certificate
resource "qrator_client_certificate" "letsencrypt" {
  client_id = var.client_id
  type      = "letsencrypt"
  domain_id = var.domain_id
  hostnames = ["example.com", "www.example.com"]
}
