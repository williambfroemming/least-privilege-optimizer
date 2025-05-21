#!/bin/bash

# --- CONFIGURATION ---
ROLE_ARN="arn:aws:iam::<AWS ACCOUNT NUMBER>:role/test-support-analyst" # Replace with your aws account number
SESSION_NAME="simulate-test-support-analyst"
REGION="us-east-1"

echo "Assuming role: $ROLE_ARN"

# --- Assume Role ---
CREDENTIALS_JSON=$(aws sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name "$SESSION_NAME" \
  --output json)

export AWS_ACCESS_KEY_ID=$(echo "$CREDENTIALS_JSON" | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDENTIALS_JSON" | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$CREDENTIALS_JSON" | jq -r '.Credentials.SessionToken')

echo "Temporary credentials exported."

# --- IAM Read Operations ---
echo "IAM: Listing users and groups..."
aws iam list-users
aws iam list-groups

echo "IAM: Getting account summary..."
aws iam get-account-summary

# --- AWS Support API (Only works if enterprise support is enabled) ---
echo "Attempting to describe AWS support cases (may fail in free-tier)..."
aws support describe-cases || echo "Skipped: support API requires Business or Enterprise plan."

# --- Cost Explorer ---
echo "Getting last week's cost and usage summary..."
aws ce get-cost-and-usage \
  --time-period Start=$(date -v-7d +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity DAILY \
  --metrics "UnblendedCost" \
  --region "$REGION"

# --- CloudWatch Logs ---
echo "Describing CloudWatch log groups and streams..."
aws logs describe-log-groups
aws logs describe-log-streams --log-group-name "/aws/lambda/your-lambda" || echo "Sample log group not found."
aws logs get-log-events \
  --log-group-name "/aws/lambda/your-lambda" \
  --log-stream-name "2024/01/01/[$LATEST]example" || echo "Sample log stream not found."

# --- EC2 Diagnostic ---
echo "Describing EC2 resources..."
aws ec2 describe-instances
aws ec2 describe-volumes
aws ec2 describe-snapshots
aws ec2 get-console-output --instance-id i-0123456789abcdef0 || echo "Sample instance ID required for get-console-output."

# --- Done ---
echo "Simulation complete. You are still operating as: $(aws sts get-caller-identity | jq -r .Arn)"
