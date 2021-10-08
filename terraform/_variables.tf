variable "name" {
  type        = string
  description = "globally unique name for this IDP instance. This is used to name most related AWS resources, so the name should be suitable for this"

  validation {
    condition     = length(var.name) > 2 && can(regex("^[a-zA-Z0-9\\-_]*$", var.name))
    error_message = "The name value can only contain alphanumeric, -, or _ ."
  }
}

variable "tags" {
  type        = map(string)
  description = "Tags to be applied to resources"
  default     = {}
}

variable "idp_lambda_package" {
  type        = string
  description = "http url, for the lambda package we should use"
  default     = "https://lstoll-lds-content-public.s3.amazonaws.com/assets/idp/terraform/___LAMBDA_SHA___.zip"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 2.1"
    }
  }
}
