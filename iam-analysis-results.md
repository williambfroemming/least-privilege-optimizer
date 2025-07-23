# IAM Analysis Results

Generated: 2025-07-22 23:11:08

## Summary
- Users analyzed: 3
- Policies updated: 3
- Total unused permissions removed: 20

## Detailed Findings

### aws_iam_user_policy.alice-analyst-test_policy
- User: alice-analyst-test
- Policy: alice-analyst-test-policy
- Unused actions: 10
- Actions: s3:PutObject, s3:DeleteObject, athena:CreateDataCatalog, athena:DeleteWorkGroup, glue:*, dynamodb:Scan, iam:List*, iam:Get* (and 2 more)

### aws_iam_user_policy.bob-dev-test_policy
- User: bob-dev-test
- Policy: bob-dev-test-policy
- Unused actions: 8
- Actions: lambda:CreateFunction, lambda:DeleteFunction, lambda:UpdateFunctionCode, s3:DeleteObject, s3:PutBucketPolicy, iam:GetRole, iam:ListRoles, logs:PutLogEvents

### aws_iam_user_policy.dave-observer-test_policy
- User: dave-observer-test
- Policy: dave-observer-test-policy
- Unused actions: 2
- Actions: glue:GetTables, cloudwatch:GetMetricData

