#!/bin/bash

# --- CONFIGURATION ---
ROLE_ARN="arn:aws:iam::<AWS ACCOUNT NUMBER>:role/test-admin" # Replace with your aws account number
SESSION_NAME="teardown-test-admin"
REGION="us-east-1"

# Assume the admin role
echo "Assuming role: $ROLE_ARN"
CREDENTIALS_JSON=$(aws sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name "$SESSION_NAME" \
  --output json)

export AWS_ACCESS_KEY_ID=$(echo "$CREDENTIALS_JSON" | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDENTIALS_JSON" | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$CREDENTIALS_JSON" | jq -r '.Credentials.SessionToken')

echo "Temporary credentials exported."

# Delete the IAM policy
echo "Deleting IAM policy: TestAdminPolicy"
POLICY_ARN=$(aws iam list-policies --scope Local --query "Policies[?PolicyName=='TestAdminPolicy'].Arn" --output text)
if [ -n "$POLICY_ARN" ]; then
  aws iam delete-policy --policy-arn "$POLICY_ARN"
else
  echo "Policy not found or already deleted."
fi

# Delete the test S3 bucket
BUCKET_NAME="test-admin-simulation-bucket"
echo "Removing all objects and deleting S3 bucket: $BUCKET_NAME"
if aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
  aws s3 rm s3://$BUCKET_NAME --recursive
  aws s3api delete-bucket --bucket "$BUCKET_NAME" --region "$REGION"
else
  echo "Bucket not found or already deleted."
fi

# Delete the CloudWatch log group
LOG_GROUP_NAME="/admin/simulation"
echo "Deleting CloudWatch log group: $LOG_GROUP_NAME"
aws logs delete-log-group --log-group-name "$LOG_GROUP_NAME" || echo "Log group not found or already deleted."

echo "Teardown complete. Resources cleaned up."
