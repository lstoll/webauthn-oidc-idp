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

variable "idp_lambda_copy_source" {
  type        = string
  description = "value in s3_object_copy source field format, for the lambda binary we should use"
  default     = "lstoll-lds-content-public/assets/idp/lambda/___LAMBDA_GIT_SHA___.zip" # sed'd
}

variable "idp_lambda_base64sha256" {
  type = string
  // https://github.com/hashicorp/terraform/issues/12443#issuecomment-366244446
  description = "base64sha256 sum of the lambda zip package. This is a terraform thing, to re-create outside of it use `openssl dgst -sha256 -binary <file> | openssl enc -base64`"
  default     = "___LAMBDA_BASE64SHA256___" # sed'd
}

variable "domain_name" {
  type        = string
  description = "Domain name the IDP is served under, used to form the issuer and the gateway routes"
}

variable "certificate_arn" {
  type        = string
  description = "ARN for the certificate to serve with"
}

variable "oidc_kms_key_arn" {
  type        = string
  description = "(optional) ARN for a asymmetric KMS key to be used for signing operations. If not provided, one will be generated. The key ARN is made available to the config via the OIDC_KMS_KEY_ARN environment variabls"
  default     = ""
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.1.0"
    }
  }
}
