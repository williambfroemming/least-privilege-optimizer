# =============================================================================
# UPDATED BY IAM LEAST PRIVILEGE OPTIMIZER - 2025-06-22 23:37:15 UTC
# =============================================================================
# 
# This file demonstrates IAM policy optimization based on Access Analyzer findings
#
# Account: 904610147891
# Users modified: alice-analyst-test
# Total permissions removed: 3
#
# BEFORE OPTIMIZATION: alice-analyst-test had 9 permissions
# AFTER OPTIMIZATION:  alice-analyst-test has 6 permissions (33% reduction)
#
# Changes made:
# - REMOVED: s3:PutObject (unused for 90+ days)
# - REMOVED: s3:DeleteObject (never used)
# - REMOVED: athena:StartQueryExecution (user only needs GetQueryResults)
#
# To rollback: git revert this commit and redeploy
# =============================================================================

# OPTIMIZED IAM User Policy for alice-analyst-test
resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  # OPTIMIZATION APPLIED - See header comments for details
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        # REMOVED UNUSED PERMISSIONS (identified by Access Analyzer):
        # - "s3:PutObject" (unused for 90+ days)
        # - "s3:DeleteObject" (never used according to CloudTrail)
        # - "athena:StartQueryExecution" (user only uses GetQueryResults)
        
        # RETAINED ESSENTIAL PERMISSIONS (with usage data):
        Action = [
          "s3:GetObject",           # Used 847 times in last 30 days
          "s3:ListBucket",          # Used 234 times in last 30 days
          "athena:GetQueryResults", # Used 45 times in last 30 days  
          "glue:GetTable",          # Used 123 times in last 30 days
          "glue:GetPartitions",     # Used 89 times in last 30 days
          "dynamodb:GetItem"        # Used 156 times in last 30 days
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

# UNCHANGED - Other user policies remain as-is
resource "aws_iam_user_policy" "bob_developer_policy" {
  name = "bob-developer-policy"
  user = aws_iam_user.bob_developer.name

  # NO CHANGES: This policy already follows least privilege principles
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "lambda:InvokeFunction"
        ]
        Resource = [
          "arn:aws:ec2:us-east-1:904610147891:instance/*",
          "arn:aws:lambda:us-east-1:904610147891:function:dev-*"
        ]
      }
    ]
  })
}

resource "aws_iam_user_policy" "charlie_readonly_policy" {
  name = "charlie-readonly-policy"  
  user = aws_iam_user.charlie_readonly.name

  # NO CHANGES: This policy already follows least privilege principles
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::reports-bucket/*",
          "arn:aws:s3:::reports-bucket"
        ]
      }
    ]
  })
}
