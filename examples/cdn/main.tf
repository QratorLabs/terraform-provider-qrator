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

  cache_query_params = {
    mode   = "ignore"
    params = ["utm_source", "utm_medium"]
  }
  redirect_code = 301

  client_headers   = ["X-Custom-Header:value"]
  client_ip_header = "X-Real-IP"
  upstream_headers = ["X-CDN-Service:Qrator"]

  content_compression = {
    gzip    = ["text/html", "text/css", "application/javascript", "application/json"]
    br      = ["*"]
    deflate = []
    zstd    = []
  }

  cache_errors = [
    {
      code    = 502
      timeout = 60000
    },
  ]

  # Omit access_filter to leave the filter unmanaged by Terraform.
  access_filter = {
    skip_ips = ["203.0.113.0/24"]

    geo    = { deny = ["CN"], deny_status_code = 451 }
    method = { allow = ["GET", "HEAD", "POST"], allow_status_code = 405 }

    uri = {
      allow             = ["^/api/", "^/static/"]
      allow_status_code = 404
      deny              = [{ regex = "^/api/internal/", status_code = 404 }]
    }

    user_agent = {
      deny        = [{ regex = "^BadBot", status_code = 429 }]
      block_empty = true
    }
  }

  webp         = 80
  tls_versions = ["TLSv1.2", "TLSv1.3"]
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
