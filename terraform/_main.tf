resource "aws_s3_bucket" "state_bucket" {
  bucket = "idp-${var.name}"
  acl    = "private"

  tags = merge({
    Name = "${var.name} State Bucket"
  }, var.tags)
}
