# S3 bucket for access logs
resource "aws_s3_bucket" "access_logs" {
  bucket = "${local.name_prefix}-access-logs-${random_id.access_logs_suffix.hex}"

  tags = merge(var.tags, {
    Purpose     = "Access logs for IAM analyzer bucket"
    Environment = var.environment
  })
}

resource "random_id" "access_logs_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_public_access_block" "access_logs_block" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs_encryption" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs_lifecycle" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "cleanup_access_logs"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 90
    }
  }
}

# S3 bucket for IAM analyzer outputs
resource "aws_s3_bucket" "iam_parser_output" {
  bucket = "${local.name_prefix}-bucket-${random_id.bucket_suffix.hex}"
  force_destroy = var.force_destroy_bucket  # Add this line
  
  tags = merge(var.tags, {
    Purpose     = "IAM least privilege scan outputs"
    Environment = var.environment
  })
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
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

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.iam_parser_output.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.iam_analyzer_key.arn
    }
    bucket_key_enabled = true
  }
}

# Object lock configuration (optional - uncomment if needed for compliance)
# resource "aws_s3_bucket_object_lock_configuration" "object_lock" {
#   bucket = aws_s3_bucket.iam_parser_output.id
#   
#   rule {
#     default_retention {
#       mode = "GOVERNANCE"
#       days = 30
#     }
#   }
# }

resource "aws_s3_bucket_logging" "access_logging" {
  bucket = aws_s3_bucket.iam_parser_output.id
  
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "lifecycle" {
  bucket = aws_s3_bucket.iam_parser_output.id

  rule {
    id     = "cleanup_old_versions"
    status = "Enabled"

    filter {
      prefix = ""
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }

  rule {
    id     = "cleanup_incomplete_uploads"
    status = "Enabled"

    filter {
      prefix = ""
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_notification" "security_notifications" {
  bucket = aws_s3_bucket.iam_parser_output.id

  topic {
    topic_arn = aws_sns_topic.security_notifications.arn
    events = [
      "s3:ObjectCreated:*",
      "s3:ObjectRemoved:*"
    ]
  }

  depends_on = [aws_sns_topic_policy.security_notifications_policy]
}