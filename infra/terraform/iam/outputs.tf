output "alice_analyst_user_arn" {
  description = "IAM ARN for alice-analyst-test"
  value       = aws_iam_user.alice_analyst_test.arn
}

output "bob_dev_user_arn" {
  description = "IAM ARN for bob-dev-test"
  value       = aws_iam_user.bob_dev_test.arn
}

output "charlie_admin_user_arn" {
  description = "IAM ARN for charlie-admin-test"
  value       = aws_iam_user.charlie_admin_test.arn
}

output "dave_observer_user_arn" {
  description = "IAM ARN for dave-observer-test"
  value       = aws_iam_user.dave_observer_test.arn
}

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
