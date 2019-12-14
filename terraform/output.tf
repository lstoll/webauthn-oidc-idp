output "base_url" {
  value = aws_api_gateway_deployment.idp.invoke_url
}

output "id_lds_li_endpoint" {
    value = aws_api_gateway_domain_name.id_lds_li.cloudfront_domain_name
}
