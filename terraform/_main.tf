locals {
  s3_config_prefix = "config/"
}

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
      KMS_OIDC_KEY_ARN = local.lambda_signer_arn
      CONFIG_BUCKET_NAME : aws_s3_bucket.state_bucket.id
      #   SESSION_TABLE_NAME: !Ref SessionTable
      #   GOOGLE_OIDC_ISSUER: "https://accounts.google.com"
      #   GOOGLE_OIDC_CLIENT_ID: !Ref GoogleOIDCClientID
      #   GOOGLE_OIDC_CLIENT_SECRET: !Ref GoogleOIDCClientSecret
    }
  }

  tags = merge({
    Name = "${var.name} IDP lambda"
  }, var.tags)
}

resource "aws_cloudwatch_log_group" "idp" {
  name = "/aws/lambda/${var.name}"

  retention_in_days = 30
}

resource "aws_iam_role" "lambda_exec" {
  name = "${var.name}-idp-lambda"

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

resource "aws_iam_policy" "idp" {
  name = "${var.name}-idp-lambda"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "kms:GetPublicKey",
          "kms:Sign",
          "kms:DescribeKey",
        ],
        "Effect" : "Allow",
        "Resource" : local.lambda_signer_arn,
      },
      {
        "Action" : [
          "s3:ListBucket",
          "s3:GetBucketLocation",
        ],
        "Effect" : "Allow",
        "Resource" : aws_s3_bucket.state_bucket.arn,
      },
      {
        "Action" : [
          "s3:GetObject",
          "s3:GetObject",
        ],
        "Effect" : "Allow",
        "Resource" : "${aws_s3_bucket.state_bucket.arn}/${local.s3_config_prefix}*",
      },
      {
        "Action" : [
          "dynamodb:BatchGet*",
          "dynamodb:DescribeStream",
          "dynamodb:DescribeTable",
          "dynamodb:Get*",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:BatchWrite*",
          "dynamodb:CreateTable",
          "dynamodb:Delete*",
          "dynamodb:Update*",
          "dynamodb:PutItem",
        ],
        "Effect" : "Allow",
        "Resource" : "${aws_dynamodb_table.sessions.arn}",
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "idp" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.idp.arn
}

resource "aws_kms_key" "lambda_signer" {
  count                    = var.oidc_kms_key_arn != "" ? 0 : 1
  description              = "${var.name} OIDC Signing Key"
  deletion_window_in_days  = 10
  customer_master_key_spec = "RSA_2048"

  tags = merge({
    Name = "${var.name} OIDC Signer"
  }, var.tags)
}

locals {
  lambda_signer_arn = var.oidc_kms_key_arn != "" ? var.oidc_kms_key_arn : aws_kms_key.lambda_signer[0].arn
}

resource "aws_dynamodb_table" "sessions" {
  name         = "${var.name}-sessions"
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = merge({
    Name = "${var.name} Sessions Table"
  }, var.tags)
}
