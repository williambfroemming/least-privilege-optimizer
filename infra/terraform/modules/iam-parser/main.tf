# Random suffix for uniqueness
resource "random_id" "suffix" {
  byte_length = 4
}

# Local values for consistent naming
locals {
  name_prefix = var.name_prefix != "" ? var.name_prefix : "iam-analyzer-${var.environment}-${random_id.suffix.hex}"
  bucket_name = var.s3_bucket_name != null ? var.s3_bucket_name : "${local.name_prefix}-output"
}

resource "aws_s3_bucket" "iam_parser_output" {
  bucket = "${local.name_prefix}-bucket"

  tags = merge(var.tags, {
    Purpose     = "IAM least privilege scan outputs"
    Environment = var.environment
  })
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket = aws_s3_bucket.iam_parser_output.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.iam_parser_output.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enhanced S3 security
resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.iam_parser_output.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true  # Optional: Reduces encryption costs
  }
}

# Enhanced lifecycle management
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle" {
  bucket = aws_s3_bucket.iam_parser_output.id

  rule {
    id     = "cleanup_old_versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    # Optional: Add transition to cheaper storage classes
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }

  # Optional: Clean up incomplete multipart uploads
  rule {
    id     = "cleanup_incomplete_uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "null_resource" "run_iam_parser" {
  provisioner "local-exec" {
    command = "python3 ${path.module}/parse_iam_tf.py ${var.tf_path}"

    environment = {
      S3_BUCKET_NAME = aws_s3_bucket.iam_parser_output.bucket
      S3_KEY_PREFIX  = var.s3_prefix
    }
  }

  triggers = {
    always_run = "${timestamp()}"
  }

  depends_on = [
    aws_s3_bucket.iam_parser_output,
    aws_s3_bucket_public_access_block.block,
    aws_s3_bucket_versioning.versioning,
    aws_s3_bucket_server_side_encryption_configuration.encryption
  ]
}