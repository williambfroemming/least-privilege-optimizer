# MODIFIED BY IAM ANALYZER - 2025-07-11 02:09:39
# File: infra/sample-iac-app/terraform/policies.tf
# Updated 3 policies, removed 20 unused permissions

resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  # OPTIMIZED POLICY - Removed 10 unused permissions
  # Original unused actions: s3:PutObject, s3:DeleteObject, athena:CreateDataCatalog, athena:DeleteWorkGroup, glue:*...
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "MinimalRequiredAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "athena:StartQueryExecution", 
          "athena:GetQueryResults",
          "cloudwatch:PutMetricData",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}


resource "aws_iam_user_policy" "bob_dev_policy" {
  name = "bob-dev-test-policy"
  user = aws_iam_user.bob_dev_test.name

  # OPTIMIZED POLICY - Removed 8 unused permissions
  # Original unused actions: lambda:CreateFunction, lambda:DeleteFunction, lambda:UpdateFunctionCode, s3:DeleteObject, s3:PutBucketPolicy...
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "MinimalRequiredAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "athena:StartQueryExecution", 
          "athena:GetQueryResults",
          "cloudwatch:PutMetricData",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}


resource "aws_iam_user_policy_attachment" "charlie_admin_access" {
  user       = aws_iam_user.charlie_admin_test.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_policy" "dave_observer_policy" {
  name = "dave-observer-test-policy"
  user = aws_iam_user.dave_observer_test.name

  # OPTIMIZED POLICY - Removed 2 unused permissions
  # Original unused actions: glue:GetTables, cloudwatch:GetMetricData
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "MinimalRequiredAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "athena:StartQueryExecution", 
          "athena:GetQueryResults",
          "cloudwatch:PutMetricData",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}