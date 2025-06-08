output "iam_s3_bucket" {
  value = var.s3_bucket_name
}

output "iam_s3_prefix" {
  value = var.s3_prefix
}

output "latest_output_key" {
  value = "${var.s3_prefix}/latest.json"
}

output "iam_lambda_function_arn" {
  value = aws_lambda_function.iam_analyzer_test.arn
}
