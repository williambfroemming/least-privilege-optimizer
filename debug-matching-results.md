# Debug: IAM Policy Matching Results

Generated: 2025-07-23 07:04:04

## Summary
- Total recommendations: 3
- Files involved: 1

## Detailed Matching Results

### alice-analyst-test
- **Finding ID**: unused-alice-permissions-001
- **User TF Name**: alice_analyst_test
- **Policy TF Name**: alice_analyst_policy
- **File Path**: infra/sample-iac-app/terraform/policies.tf
- **Unused Actions**: 10
- **Actions**: s3:PutObject, s3:DeleteObject, athena:CreateDataCatalog, athena:DeleteWorkGroup, glue:*, dynamodb:Scan, iam:List*, iam:Get*...

### bob-dev-test
- **Finding ID**: unused-bob-permissions-002
- **User TF Name**: bob_dev_test
- **Policy TF Name**: bob_dev_policy
- **File Path**: infra/sample-iac-app/terraform/policies.tf
- **Unused Actions**: 8
- **Actions**: lambda:CreateFunction, lambda:DeleteFunction, lambda:UpdateFunctionCode, s3:DeleteObject, s3:PutBucketPolicy, iam:GetRole, iam:ListRoles, logs:PutLogEvents

### dave-observer-test
- **Finding ID**: unused-dave-permissions-003
- **User TF Name**: dave_observer_test
- **Policy TF Name**: dave_observer_policy
- **File Path**: infra/sample-iac-app/terraform/policies.tf
- **Unused Actions**: 2
- **Actions**: glue:GetTables, cloudwatch:GetMetricData
