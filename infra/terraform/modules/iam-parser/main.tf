resource "aws_s3_bucket" "iam_parser_output" {
  bucket = var.s3_bucket_name

  tags = {
    Purpose = "IAM least privilege scan outputs"
  }
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

resource "null_resource" "run_iam_parser" {
  provisioner "local-exec" {
    command = "python3 ${path.module}/parse_iam_tf.py ${var.tf_path}"

    environment = {
      S3_BUCKET_NAME = var.s3_bucket_name
      S3_KEY_PREFIX  = var.s3_prefix
    }
  }

  triggers = {
    always_run = "${timestamp()}"
  }

  depends_on = [
    aws_s3_bucket.iam_parser_output,
    aws_s3_bucket_public_access_block.block,
    aws_s3_bucket_versioning.versioning
  ]
}
