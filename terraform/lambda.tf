resource "aws_lambda_function" "idp" {
  filename      = "files/idp.zip"
  function_name = "idp"
  role          = aws_iam_role.idp_lambda.arn
  handler       = "idp"

  source_code_hash = filebase64sha256("files/idp.zip")

  runtime = "go1.x"

  environment {
    variables = {
      foo = "bar"
    }
  }
}

resource "aws_cloudwatch_log_group" "example" {
  name              = "/aws/lambda/${aws_lambda_function.idp.function_name}"
  retention_in_days = 14
}

resource "aws_lambda_permission" "apigw" {
  statement_id     = "AllowAPIGatewayInvoke"
  action           = "lambda:InvokeFunction"
  function_name    = aws_lambda_function.idp.function_name
  principal        = "apigateway.amazonaws.com"

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${aws_api_gateway_rest_api.idp.execution_arn}/*/*"
}
