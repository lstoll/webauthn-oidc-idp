resource "aws_api_gateway_rest_api" "idp" {
  name        = "IDP"
  description = "IDP Gateway"
}

resource "aws_api_gateway_resource" "idpproxy" {
  rest_api_id = aws_api_gateway_rest_api.idp.id
  parent_id   = aws_api_gateway_rest_api.idp.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "idpproxy" {
  rest_api_id   = aws_api_gateway_rest_api.idp.id
  resource_id   = aws_api_gateway_resource.idpproxy.id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "idp_lambda" {
  rest_api_id = aws_api_gateway_rest_api.idp.id
  resource_id = aws_api_gateway_method.idpproxy.resource_id
  http_method = aws_api_gateway_method.idpproxy.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.idp.invoke_arn
}

resource "aws_api_gateway_method" "idpproxy_root" {
  rest_api_id   = aws_api_gateway_rest_api.idp.id
  resource_id   = aws_api_gateway_rest_api.idp.root_resource_id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "idp_lambda_root" {
  rest_api_id = aws_api_gateway_rest_api.idp.id
  resource_id = aws_api_gateway_method.idpproxy_root.resource_id
  http_method = aws_api_gateway_method.idpproxy_root.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.idp.invoke_arn
}

resource "aws_api_gateway_deployment" "idp" {
  depends_on = [
    aws_api_gateway_integration.idp_lambda,
    aws_api_gateway_integration.idp_lambda_root,
  ]

  rest_api_id = aws_api_gateway_rest_api.idp.id
  stage_name  = "prod"
}

resource "aws_api_gateway_domain_name" "id_lds_li" {
  certificate_arn = var.gateway_cert_arn
  domain_name     = "id.lds.li"
}

resource "aws_api_gateway_base_path_mapping" "idp" {
  api_id      = aws_api_gateway_rest_api.idp.id
  domain_name = aws_api_gateway_domain_name.id_lds_li.domain_name

  stage_name  = "prod"
}
