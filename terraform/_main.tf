resource "aws_s3_bucket" "state_bucket" {
  bucket = var.name
  acl    = "private"

  tags = merge({
    Name = "${var.name} State Bucket"
  }, var.tags)
}

resource "aws_s3_object_copy" "idp_lambda_zip" {
  bucket = aws_s3_bucket.state_bucket.bucket
  key    = "lambda/idp.zip"
  source = var.idp_lambda_copy_source
}

resource "aws_lambda_function" "idp" {
  function_name = "idp-${var.name}"

  s3_bucket = aws_s3_bucket.state_bucket.id
  s3_key    = aws_s3_object_copy.idp_lambda_zip.key

  runtime = "go1.x"
  handler = "idp"

  source_code_hash = var.idp_lambda_base64sha256

  role = aws_iam_role.lambda_exec.arn

  environment {
    variables = {
      # LOCAL_DEVELOPMENT_MODE: "false" # used in dev
      #   BASE_URL: !Sub "https://${DomainName}"
      #   KMS_OIDC_KEY_ARN: !Ref OIDCSignerKeyARN
      #   CONFIG_BUCKET_NAME: !Ref ConfigBucket
      #   SESSION_TABLE_NAME: !Ref SessionTable
      #   GOOGLE_OIDC_ISSUER: "https://accounts.google.com"
      #   GOOGLE_OIDC_CLIENT_ID: !Ref GoogleOIDCClientID
      #   GOOGLE_OIDC_CLIENT_SECRET: !Ref GoogleOIDCClientSecret
    }
  }

}

resource "aws_cloudwatch_log_group" "idp" {
  name = "/aws/lambda/${var.name}"

  retention_in_days = 30
}

resource "aws_iam_role" "lambda_exec" {
  name = "${var.name}-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Sid    = ""
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
