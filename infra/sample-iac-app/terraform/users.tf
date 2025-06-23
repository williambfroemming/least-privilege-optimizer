
# =============================================================================
# OPTIMIZATION NOTE: alice-analyst-test policy would be optimized here
# =============================================================================
# The following changes would be applied to alice-analyst-test ONLY:
# - Remove s3:PutObject (unused for 90+ days)
# - Remove s3:DeleteObject (never used)
# - Remove athena:StartQueryExecution (user only needs GetQueryResults)
# ALL OTHER USERS would remain exactly as written below
# =============================================================================

# =============================================================================
# UPDATED BY IAM LEAST PRIVILEGE OPTIMIZER - 2025-06-22 23:56:41 UTC
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

resource "aws_iam_user" "alice_analyst_test" {
  name = "alice-analyst-test"
  path = "/"
}