# IAM Analysis Results

Generated: 2025-06-26 18:48:10

## Summary
- Users analyzed: 2
- Policies updated: 2
- Files modified: 1
- Total unused permissions removed: 18

## Files Modified

### infra/sample-iac-app/terraform/policies.tf
- Policies updated: 2
- Unused permissions removed: 18
  - **alice-analyst-test** (alice_analyst_policy): 10 unused actions
  - **bob-dev-test** (bob_dev_policy): 8 unused actions

## Detailed Findings

### aws_iam_user_policy.alice_analyst_policy
- User: alice-analyst-test
- Policy: alice-analyst-test-policy
- File: infra/sample-iac-app/terraform/policies.tf
- Unused actions: 10
- Actions: s3:PutObject, s3:DeleteObject, athena:CreateDataCatalog, athena:DeleteWorkGroup, glue:*, dynamodb:Scan, iam:List*, iam:Get* (and 2 more)

### aws_iam_user_policy.bob_dev_policy
- User: bob-dev-test
- Policy: bob-dev-test-policy
- File: infra/sample-iac-app/terraform/policies.tf
- Unused actions: 8
- Actions: lambda:CreateFunction, lambda:DeleteFunction, lambda:UpdateFunctionCode, s3:DeleteObject, s3:PutBucketPolicy, iam:GetRole, iam:ListRoles, logs:PutLogEvents
