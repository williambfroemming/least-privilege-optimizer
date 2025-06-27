# IAM Analysis Results

Generated: 2025-06-26 18:44:20

## Summary
- Users analyzed: 2
- Policies updated: 2
- Files modified: 1
- Total unused permissions removed: 6

## Files Modified

### test-policies.tf
- Policies updated: 2
- Unused permissions removed: 6
  - **alice-test-user** (alice_test_policy): 4 unused actions
  - **bob-test-user** (bob_test_policy): 2 unused actions

## Detailed Findings

### aws_iam_user_policy.alice_test_policy
- User: alice-test-user
- Policy: alice-test-policy
- File: test-policies.tf
- Unused actions: 4
- Actions: s3:PutObject, s3:DeleteObject, dynamodb:Scan, iam:List*

### aws_iam_user_policy.bob_test_policy
- User: bob-test-user
- Policy: bob-test-policy
- File: test-policies.tf
- Unused actions: 2
- Actions: lambda:CreateFunction, lambda:DeleteFunction
