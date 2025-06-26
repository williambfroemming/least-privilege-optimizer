# S3 Outputs
output "s3_bucket_name" {
  description = "Name of the S3 bucket created for IAM analysis outputs"
  value       = aws_s3_bucket.iam_parser_output.bucket
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.iam_parser_output.arn
}

output "s3_bucket_domain_name" {
  description = "Domain name of the S3 bucket"
  value       = aws_s3_bucket.iam_parser_output.bucket_domain_name
}

output "s3_prefix" {
  description = "S3 prefix for storing analysis outputs"
  value       = var.s3_prefix
}

output "latest_output_key" {
  description = "S3 key for the latest analysis output"
  value       = "${var.s3_prefix}/latest.json"
}

# Lambda Outputs (conditional)
output "lambda_function_arn" {
  description = "ARN of the IAM Analyzer Lambda function"
  value       = var.create_lambda ? aws_lambda_function.iam_analyzer_engine_tf_deployed[0].arn : null
}

output "lambda_function_name" {
  description = "Name of the IAM Analyzer Lambda function"
  value       = var.create_lambda ? aws_lambda_function.iam_analyzer_engine_tf_deployed[0].function_name : null
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = var.create_lambda ? aws_iam_role.iam_analyzer_lambda_role[0].arn : null
}

# Utility Outputs
output "name_prefix" {
  description = "Generated name prefix used for resources"
  value       = local.name_prefix
}

output "aws_region" {
  description = "AWS region where resources are deployed"
  value       = data.aws_region.current.name
}

output "aws_account_id" {
  description = "AWS account ID where resources are deployed"
  value       = data.aws_caller_identity.current.account_id
}

output "github_token_ssm_path" {
  description = "SSM parameter path where GitHub token should be stored"
  value       = var.github_token_ssm_path
}

output "schedule_expression" {
  description = "EventBridge schedule expression for automated runs"
  value       = var.schedule_expression
}

output "setup_commands" {
  description = "Commands to complete setup"
  value = var.create_lambda ? [
    "# Store your GitHub token:",
    "aws ssm put-parameter --name '${var.github_token_ssm_path}' --value 'your_github_token_here' --type SecureString",
    "",
    "# Test the Lambda manually:",
    "aws lambda invoke --function-name '${aws_lambda_function.iam_analyzer_engine_tf_deployed[0].function_name}' response.json"
  ] : []
}