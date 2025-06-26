# Optimized IAM Policies - 2025-06-25

resource "aws_iam_user_policy" "alice_analyst_test_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  # Optimized policy - removed 10 unused permissions
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "athena:StartQueryExecution",
          "athena:GetQueryResults",
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}

