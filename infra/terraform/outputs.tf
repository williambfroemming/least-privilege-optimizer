output "github_actions_role_arn" {
  description = "IAM role ARN for GitHub Actions OIDC"
  value       = aws_iam_role.github_actions_least_privilege.arn
}

output "lambda_execution_role_arn" {
  description = "IAM role ARN for Lambda basic execution"
  value       = aws_iam_role.lambda_basic_execution.arn
}

output "github_oidc_provider_arn" {
  description = "OIDC provider ARN for GitHub Actions"
  value       = aws_iam_openid_connect_provider.github_actions.arn
}
