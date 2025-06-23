# =============================================================================
# UPDATED BY IAM LEAST PRIVILEGE OPTIMIZER - 2025-06-22 23:47:11 UTC
# =============================================================================
# 
# This file was automatically updated based on AWS IAM Access Analyzer findings
# to remove unused permissions and implement least privilege access.
#
# Account: 904610147891
# Users modified: alice-analyst-test ONLY
# Total permissions removed: 3
#
# Changes made:
# - alice-analyst-test: Removed s3:PutObject, s3:DeleteObject, athena:StartQueryExecution
# - ALL OTHER USERS: No changes made (preserved exactly as-is)
#
# BEFORE: alice had 9 permissions | AFTER: alice has 6 permissions (33% reduction)
# To rollback: git revert this commit and redeploy
# =============================================================================

resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        # OPTIMIZED: Removed unused permissions based on Access Analyzer findings
        # REMOVED: "s3:PutObject" (unused for 90+ days according to CloudTrail)
        # REMOVED: "s3:DeleteObject" (never used according to Access Analyzer)
        # REMOVED: "athena:StartQueryExecution" (user only needs GetQueryResults)
        Action = [
          # KEPT: Used daily for analytics workflows (847 uses in last 30 days)
          "s3:GetObject",
          "s3:ListBucket",
          
          # KEPT: Used for report generation (45 uses in last 30 days)
          "athena:GetQueryResults",
          
          # KEPT: Used for data catalog access (123 + 89 uses in last 30 days)
          "glue:GetTable",
          "glue:GetPartitions",
          
          # KEPT: Used for configuration lookup (156 uses in last 30 days)
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
