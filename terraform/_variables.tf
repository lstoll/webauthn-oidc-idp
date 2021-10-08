variable "lambda_copy_source" {
  type        = string
  description = "value in s3_object_copy source field format, for the lambda binary we should use"
  default     = "lstoll-lds-content-public/assets/idp/___LAMBDA_SHA___.zip" # sed'd
}
