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

variable "service_id" {
  type = number
}

# --- Service name and access policy ---

resource "qrator_service" "example" {
  id   = var.service_id
  name = "my-service"
}

# --- Service status ---

resource "qrator_service_status" "example" {
  service_id = var.service_id
  status     = "online"
}

# --- Service services (full example) ---

resource "qrator_service_services" "example" {
  service_id = var.service_id

  dns = [
    {
      port = 53
    },
  ]

  http = [
    {
      port         = 80
      upstream_ssl = false
    },
    {
      port         = 443
      ssl          = true
      http2        = true
      upstream_ssl = true
    },
  ]

  icmp = [
    {
      rate_limit = 80000
    },
  ]

  nat = [
    {
      port  = 53
      proto = "udp"
    },
    {
      port  = 25
      proto = "tcp"
    },
  ]

  any_ingress_egress = [
    {
      rate_limit = 80000
      drop_amp   = true
    },
  ]

  tcp_ingress_egress = [
    {},
  ]

  tcp_egress = [
    {},
  ]

  frag_ingress_egress = [
    {
      rate_limit = 80000
    },
  ]
}

# --- Service upstream IPs ---

resource "qrator_service_ips" "example" {
  service_id = var.service_id

  ips = [
    "192.0.2.1",
    "198.51.100.12",
  ]
}

# --- Service SNI ---

resource "qrator_service_sni" "example" {
  service_id = var.service_id

  links = [
    {
      certificate = qrator_client_certificate.svc_cert.id
    },
    {
      host        = "service.example.com"
      certificate = qrator_client_certificate.svc_cert.id
    },
  ]
}

# --- Service whitelist / blacklist ---

resource "qrator_service_whitelist" "example" {
  service_id = var.service_id

  entries = [
    {
      ip      = "203.0.113.10"
      comment = "Office gateway"
    },
  ]
}

resource "qrator_service_blacklist" "example" {
  service_id = var.service_id

  entries = [
    {
      ip      = "192.0.2.100"
      comment = "Known attacker"
    },
  ]
}

# --- Certificate (referenced by SNI) ---

resource "qrator_client_certificate" "svc_cert" {
  client_id = 67890
  type      = "upload"

  certificates {
    cert = file("cert.pem")
    key  = file("key.pem")
  }
}
