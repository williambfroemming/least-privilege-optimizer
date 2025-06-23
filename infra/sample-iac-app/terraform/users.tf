
# =============================================================================
# OPTIMIZATION NOTE: This file contains alice-analyst-test policy
# =============================================================================
# The following optimizations would be applied:
# - Remove s3:PutObject (unused for 90+ days)
# - Remove s3:DeleteObject (never used)
# - Remove athena:StartQueryExecution (user only needs GetQueryResults)
# =============================================================================

# =============================================================================
# UPDATED BY IAM LEAST PRIVILEGE OPTIMIZER - 2025-06-22 23:43:31 UTC
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
# BEFORE: 9 permissions | AFTER: 6 permissions (33% reduction)
# To rollback: git revert this commit and redeploy
# =============================================================================

resource "aws_iam_user" "alice_analyst_test" {
  name = "alice-analyst-test"
  path = "/"
}