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
  description = "The ARN of the deployed IAM Analyzer Lambda function"
  value       = aws_lambda_function.iam_analyzer_engine_tf_deployed.arn
}

output "lambda_function_name" {
  description = "The name of the deployed IAM Analyzer Lambda function"
  value       = aws_lambda_function.iam_analyzer_engine_tf_deployed.function_name
}