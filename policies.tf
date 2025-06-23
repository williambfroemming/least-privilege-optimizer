# =============================================================================
# UPDATED BY IAM LEAST PRIVILEGE OPTIMIZER - 2025-06-22 23:30:46 UTC
# =============================================================================
# 
# This file was automatically updated based on AWS IAM Access Analyzer findings
# to remove unused permissions and implement least privilege access.
#
# Account: 904610147891
# Users modified: alice-analyst-test
# Total permissions removed: 3
#
# Changes made:
# - alice-analyst-test: Removed s3:PutObject, s3:DeleteObject, athena:StartQueryExecution
#
# To rollback: git revert this commit and redeploy
# =============================================================================

# IAM User Policies (Optimized)
resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  # OPTIMIZED: Removed unused permissions based on Access Analyzer findings
  # REMOVED: s3:PutObject, s3:DeleteObject, athena:StartQueryExecution
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # KEPT: Used daily for analytics workflows (847 uses in 30 days)
          "s3:GetObject",
          "s3:ListBucket",
          
          # KEPT: Used for report generation (45 uses in 30 days)
          "athena:GetQueryResults",
          
          # KEPT: Used for data catalog access (123 uses in 30 days)
          "glue:GetTable",
          "glue:GetPartitions",
          
          # KEPT: Used for configuration lookup (156 uses in 30 days)
          "dynamodb:GetItem"
        ]
        Resource = [
          "arn:aws:s3:::analytics-bucket/*",
          "arn:aws:s3:::analytics-bucket",
          "arn:aws:glue:us-east-1:904610147891:table/test-database/*",
          "arn:aws:dynamodb:us-east-1:904610147891:table/config-table"
        ]
      }
    ]
  })
}

resource "aws_iam_user_policy" "test_user_policy" {
  name = "static-parser-test-user-policy"
  user = aws_iam_user.test_user.name

  # NO CHANGES: Policy already follows least privilege principles
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "dynamodb:GetItem"
        ]
        Resource = [
          "arn:aws:s3:::test-bucket/*",
          "arn:aws:dynamodb:us-east-1:904610147891:table/test-table"
        ]
      }
    ]
  })
}
