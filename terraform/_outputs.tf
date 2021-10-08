output "s3_bucket" {
  // TODO - do we want to make this something people can manage externally?
  description = "S3 Bucket used for IDP storage"
  value       = aws_s3_bucket.state_bucket.bucket
}

output "s3_bucket_config_prefix" {
  description = "S3 prefix for config related items inside the app bucket"
  value       = local.s3_config_prefix
}

output "gateway_domain_name" {
  description = "Name to alias the DNS record to"

  value = aws_apigatewayv2_domain_name.default.domain_name_configuration.0.target_domain_name
}

output "gateway_hosted_zone_id" {
  description = "Hosted Zone ID for the domain"

  value = aws_apigatewayv2_domain_name.default.domain_name_configuration.0.hosted_zone_id
}
