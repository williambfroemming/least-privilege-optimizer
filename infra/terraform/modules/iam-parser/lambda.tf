resource "aws_lambda_function" "iam_analyzer_engine_tf_deployed" {
  function_name = "iam-analyzer-engine_tf_deployed"
  role          = aws_iam_role.iam_analyzer_lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 10

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      S3_BUCKET = aws_s3_bucket.iam_parser_output.bucket
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_logs_attach,
    aws_iam_role_policy_attachment.access_analyzer_attach,
    aws_iam_role_policy_attachment.lambda_s3_access_attach
  ]
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/build"
  output_path = "${path.module}/lambda/iam_analyzer_engine.zip"

  excludes = [
    "test",
    ".env.example",
    "README.md",
    "__pycache__"
  ]
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/iam-analyzer-engine_tf_deployed"
  retention_in_days = 14
}
