# KMS key for S3 encryption
resource "aws_kms_key" "iam_analyzer_key" {
  description             = "KMS key for IAM analyzer S3 bucket encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(var.tags, {
    Purpose     = "IAM analyzer S3 encryption"
    Environment = var.environment
  })
}

resource "aws_kms_alias" "iam_analyzer_key_alias" {
  name          = "alias/${local.name_prefix}-s3-key"
  target_key_id = aws_kms_key.iam_analyzer_key.key_id
}