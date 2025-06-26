terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.1"
    }
  }
}

# Random suffix for uniqueness
resource "random_id" "suffix" {
  byte_length = 4
}

# Local values for consistent naming
locals {
  name_prefix = var.name_prefix != "" ? var.name_prefix : "iam-analyzer-${var.environment}-${random_id.suffix.hex}"
  bucket_name = var.s3_bucket_name != null ? var.s3_bucket_name : "${local.name_prefix}-output"
  
  common_tags = merge(var.tags, {
    Module      = "iam-parser"
    Environment = var.environment
    CreatedBy   = "terraform"
    Timestamp   = timestamp()
  })
}

# IAM parser execution
resource "null_resource" "run_iam_parser" {
  provisioner "local-exec" {
    command = "python3 ${path.module}/scripts/parse_iam_tf.py ${var.tf_path}"

    environment = {
      S3_BUCKET_NAME = aws_s3_bucket.iam_parser_output.bucket
      S3_KEY_PREFIX  = var.s3_prefix
    }
  }

  triggers = {
    # Use a directory hash or timestamp instead of filemd5 for directories
    tf_path_dir   = var.tf_path
    bucket_name   = aws_s3_bucket.iam_parser_output.bucket
    s3_prefix     = var.s3_prefix
  }

  depends_on = [
    aws_s3_bucket.iam_parser_output,
    aws_s3_bucket_public_access_block.block,
    aws_s3_bucket_versioning.versioning,
    aws_s3_bucket_server_side_encryption_configuration.encryption
  ]
}