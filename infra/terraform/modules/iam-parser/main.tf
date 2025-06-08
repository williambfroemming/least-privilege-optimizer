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

resource "aws_iam_role" "lambda_exec" {
  name = "${var.lambda_function_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "lambda.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "lambda_s3_access" {
  name = "${var.lambda_function_name}-s3-access"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = ["s3:GetObject"],
        Resource = "arn:aws:s3:::${var.s3_bucket_name}/${var.s3_prefix}/*"
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_s3_access.arn
}

resource "aws_lambda_function" "iam_analyzer_test" {
  function_name    = var.lambda_function_name
  filename         = "${path.root}/${var.lambda_zip_path}"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.11"
  source_code_hash = filebase64sha256("${path.root}/${var.lambda_zip_path}")
  timeout          = 15

  environment {
    variables = {
      S3_BUCKET = var.s3_bucket_name
      S3_KEY    = "${var.s3_prefix}/latest.json"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_policy_attach
  ]
}
