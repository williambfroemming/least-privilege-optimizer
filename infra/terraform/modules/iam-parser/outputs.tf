# outputs.tf - Updated for multi-function architecture

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

# Lambda Outputs (updated for multi-function architecture)
output "lambda_function_arns" {
  description = "ARNs of all IAM Analyzer Lambda functions"
  value = var.create_lambda ? {
    for key, func in aws_lambda_function.iam_analyzer_functions : key => func.arn
  } : {}
}

output "lambda_function_names" {
  description = "Names of all IAM Analyzer Lambda functions"
  value = var.create_lambda ? {
    for key, func in aws_lambda_function.iam_analyzer_functions : key => func.function_name
  } : {}
}

# Individual function outputs for backward compatibility
output "lambda_function_arn" {
  description = "ARN of the S3 reader Lambda function (backward compatibility)"
  value       = var.create_lambda ? try(aws_lambda_function.iam_analyzer_functions["read-s3"].arn, null) : null
}

output "lambda_function_name" {
  description = "Name of the S3 reader Lambda function (backward compatibility)"
  value       = var.create_lambda ? try(aws_lambda_function.iam_analyzer_functions["read-s3"].function_name, null) : null
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

# CloudTrail Lake Outputs
output "cloudtrail_event_data_store_arn" {
  description = "ARN of the CloudTrail Lake Event Data Store"
  value       = aws_cloudtrail_event_data_store.iam_analyzer_store.arn
}

output "cloudtrail_event_data_store_name" {
  description = "Name of the CloudTrail Lake Event Data Store"
  value       = aws_cloudtrail_event_data_store.iam_analyzer_store.name
}

# Sample queries for CloudTrail Lake
output "sample_queries" {
  description = "Sample SQL queries for CloudTrail Lake analysis"
  value = {
    iam_usage_query = local.iam_usage_query
    user_frequency_query = local.user_frequency_query
    unused_permissions_query = local.unused_permissions_query
  }
}

# Updated setup commands for multi-function architecture
output "setup_commands" {
  description = "Commands to complete setup"
  value = var.create_lambda ? concat([
    "# Store your GitHub token:",
    "aws ssm put-parameter --name '${var.github_token_ssm_path}' --value 'your_github_token_here' --type SecureString",
    "",
    "# Test individual Lambda functions:",
    "aws lambda invoke --function-name '${local.name_prefix}-read-s3' response.json",
    "aws lambda invoke --function-name '${local.name_prefix}-start-cloudtrail' response.json",
    "",
    "# Or test the full Step Function workflow:",
    var.create_step_function ? "aws stepfunctions start-execution --state-machine-arn '${aws_sfn_state_machine.iam_analyzer[0].arn}' --input '{}'" : "# Step Function not enabled",
    "",
    "# CloudTrail Lake Setup:",
    "# 1. Data starts appearing immediately in CloudTrail Lake",
    "# 2. You can query directly using SQL in the CloudTrail console or AWS CLI",
    "# 3. Example query to test:",
    "aws cloudtrail start-query --query-statement \"SELECT eventTime, eventName, eventSource FROM ${aws_cloudtrail_event_data_store.iam_analyzer_store.arn} WHERE eventTime > '${formatdate("YYYY-MM-DD", timeadd(timestamp(), "-24h"))}' LIMIT 10\""
  ]) : [
    "# CloudTrail Lake Setup:",
    "# 1. Data starts appearing immediately in CloudTrail Lake", 
    "# 2. You can query directly using SQL in the CloudTrail console or AWS CLI"
  ]
}

# Step Function Outputs - REMOVED from here since they're now in step_function.tf
# This eliminates the duplicate output error

# Multi-function architecture summary
output "architecture_summary" {
  description = "Summary of the multi-function architecture"
  value = var.create_lambda ? {
    total_functions = length(local.lambda_functions)
    function_names = keys(local.lambda_functions)
    step_function_enabled = var.create_step_function
  } : {
    total_functions = 0
    function_names = []
    step_function_enabled = false
  }
}

output "step_function_console_url" {
  description = "AWS Console URL for the Step Function"
  value       = var.create_step_function && var.create_lambda ? "https://${data.aws_region.current.name}.console.aws.amazon.com/states/home?region=${data.aws_region.current.name}#/statemachines/view/${aws_sfn_state_machine.iam_analyzer[0].arn}" : null
}

output "step_function_arn" {
  description = "ARN of the Step Function state machine"
  value       = var.create_step_function && var.create_lambda ? aws_sfn_state_machine.iam_analyzer[0].arn : null
}

output "step_function_name" {
  description = "Name of the Step Function state machine"
  value       = var.create_step_function && var.create_lambda ? aws_sfn_state_machine.iam_analyzer[0].name : null
}