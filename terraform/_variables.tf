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

variable "lambda_copy_source" {
  type        = string
  description = "value in s3_object_copy source field format, for the lambda binary we should use"
  default     = "lstoll-lds-content-public/assets/idp/___LAMBDA_SHA___.zip" # sed'd
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}
