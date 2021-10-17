resource "aws_apigatewayv2_api" "idp" {
  name          = var.name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_api_mapping" "idp" {
  api_id      = aws_apigatewayv2_api.idp.id
  domain_name = aws_apigatewayv2_domain_name.default.id
  stage       = aws_apigatewayv2_stage.idp.id
}

resource "aws_apigatewayv2_domain_name" "default" {
  domain_name = var.domain_name

  domain_name_configuration {
    certificate_arn = var.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
}

resource "aws_apigatewayv2_stage" "idp" {
  api_id = aws_apigatewayv2_api.idp.id

  name        = var.name
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gw.arn

    format = jsonencode({
      requestId               = "$context.requestId"
      sourceIp                = "$context.identity.sourceIp"
      requestTime             = "$context.requestTime"
      protocol                = "$context.protocol"
      httpMethod              = "$context.httpMethod"
      resourcePath            = "$context.resourcePath"
      routeKey                = "$context.routeKey"
      status                  = "$context.status"
      responseLength          = "$context.responseLength"
      integrationErrorMessage = "$context.integrationErrorMessage"
      }
    )
  }
}

resource "aws_apigatewayv2_integration" "idp" {
  api_id = aws_apigatewayv2_api.idp.id

  integration_uri    = aws_lambda_function.idp.invoke_arn
  integration_type   = "AWS_PROXY"
  integration_method = "POST"
}

resource "aws_cloudwatch_log_group" "api_gw" {
  name = "/aws/api_gw/${var.name}"

  retention_in_days = 30
}

resource "aws_lambda_permission" "api_gw" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.idp.function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.idp.execution_arn}/*/*"
}

/**********
*
* Routes
*
***********/

resource "aws_apigatewayv2_route" "oidc_discovery" {
  api_id = aws_apigatewayv2_api.idp.id

  route_key = "GET /.well-known/openid-configuration"
  target    = "integrations/${aws_apigatewayv2_integration.idp.id}"
}

resource "aws_apigatewayv2_route" "oidc_keys" {
  api_id = aws_apigatewayv2_api.idp.id

  route_key = "GET /keys"
  target    = "integrations/${aws_apigatewayv2_integration.idp.id}"
}

resource "aws_apigatewayv2_route" "auth_start" {
  api_id = aws_apigatewayv2_api.idp.id

  route_key = "GET /auth"
  target    = "integrations/${aws_apigatewayv2_integration.idp.id}"
}

resource "aws_apigatewayv2_route" "callback" {
  api_id = aws_apigatewayv2_api.idp.id

  route_key = "GET /callback"
  target    = "integrations/${aws_apigatewayv2_integration.idp.id}"
}

resource "aws_apigatewayv2_route" "token" {
  api_id = aws_apigatewayv2_api.idp.id

  route_key = "POST /token"
  target    = "integrations/${aws_apigatewayv2_integration.idp.id}"
}

resource "aws_apigatewayv2_route" "webauthn" {
  api_id = aws_apigatewayv2_api.idp.id

  route_key = "ANY /webauthn/{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.idp.id}"
}

resource "aws_apigatewayv2_route" "providers" {
  api_id = aws_apigatewayv2_api.idp.id

  route_key = "ANY /provider/{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.idp.id}"
}
