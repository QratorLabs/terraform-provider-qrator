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

resource "qrator_cdn" "test" {
  domain_id     = var.domain_id
  cache_control = false
}
