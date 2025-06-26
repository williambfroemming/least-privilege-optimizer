# IAM Analysis Results

Generated: 2025-06-25 20:10:32

## Summary
- Users analyzed: 1
- Unused permissions: 10

## Findings

### aws_iam_user.alice_analyst_test
- User: alice-analyst-test
- Unused actions: 10
- Actions: s3:PutObject, s3:DeleteObject, athena:CreateDataCatalog, athena:DeleteWorkGroup, glue:* (and 5 more)
