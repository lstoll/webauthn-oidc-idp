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
