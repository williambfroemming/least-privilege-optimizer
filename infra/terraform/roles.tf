resource "aws_iam_role" "github_actions_least_privilege" {
  name = "GitHubActions-LeastPrivilegeRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Federated = "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com"
        },
        Action = "sts:AssumeRoleWithWebIdentity",
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          },
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:williambfroemming/least-privilege-optimizer:*"
          }
        }
      }
    ]
  })

  tags = {
    Environment = "development"
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_role" "lambda_basic_execution" {
  name = "lambda-basic-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Environment = "development"
    ManagedBy   = "terraform"
  }
}
