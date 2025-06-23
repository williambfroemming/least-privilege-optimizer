# =============================================================================
# UPDATED BY IAM LEAST PRIVILEGE OPTIMIZER - 2025-06-22 23:17:08 UTC
# =============================================================================
# 
# This file was automatically updated based on AWS IAM Access Analyzer findings
# to remove unused permissions and implement least privilege access.
#
# Users modified: alice-analyst-test
# Total permissions removed: 3
#
# Changes made:
# - alice-analyst-test: Removed 3 unused permissions
#
# To rollback: git revert this commit and redeploy
# =============================================================================


# User from users.tf
resource "aws_iam_user" "alice_analyst_test" {
  name = "alice-analyst-test"
  path = "/test-users/"
  
  tags = {
    Purpose = "IAM-Analyzer-Testing"
    SourceFile = "users.tf"
    Environment = "Test"
  }
}

resource "aws_iam_user_policy" "alice_analyst_test_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "athena:GetQueryResults",
          "glue:GetTable",
          "glue:GetPartitions",
          "dynamodb:GetItem"
        ]
        Resource = [
          "arn:aws:s3:::analytics-bucket/*",
          "arn:aws:s3:::analytics-bucket",
          "arn:aws:glue:us-east-1:904610147891:table/test-database/*"
        ]
      }
    ]
  })
}

# User from main.tf
resource "aws_iam_user" "test_user" {
  name = "static-parser-test-user"
  path = "/test-users/"
  
  tags = {
    Purpose = "IAM-Analyzer-Testing"
    SourceFile = "main.tf"
    Environment = "Test"
  }
}

resource "aws_iam_user_policy" "test_user_policy" {
  name = "static-parser-test-user-policy"
  user = aws_iam_user.test_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "athena:StartQueryExecution",
          "athena:GetQueryResults",
          "glue:GetTable",
          "glue:GetPartitions",
          "dynamodb:GetItem"
        ]
        Resource = [
          "arn:aws:s3:::analytics-bucket/*",
          "arn:aws:s3:::analytics-bucket",
          "arn:aws:glue:us-east-1:904610147891:table/test-database/*"
        ]
      }
    ]
  })
}
