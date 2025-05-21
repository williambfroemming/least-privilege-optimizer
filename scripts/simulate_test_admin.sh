#!/bin/bash

# --- CONFIGURATION ---
ROLE_ARN="arn:aws:iam::<AWS ACCOUNT NUMBER>:role/test-admin" # Replace with your aws account number
SESSION_NAME="simulate-test-admin"
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

# IAM operations
echo "Creating test IAM policy..."
aws iam create-policy \
  --policy-name TestAdminPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:ListAllMyBuckets"],
      "Resource": "*"
    }]
  }' || echo "Policy may already exist."

echo "Listing all IAM roles..."
aws iam list-roles

# S3 bucket operations
echo "Creating test S3 bucket (if not already created)..."
aws s3api create-bucket \
  --bucket test-admin-simulation-bucket \
  --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION" || echo "Bucket may already exist."

echo "Tagging the test bucket..."
aws s3api put-bucket-tagging \
  --bucket test-admin-simulation-bucket \
  --tagging 'TagSet=[{Key=Environment,Value=Test}]'

# CloudWatch Logs: create log group
echo "Creating a CloudWatch log group..."
aws logs create-log-group --log-group-name "/admin/simulation" || echo "Log group may already exist."

# EC2: Describe security groups and AMIs
echo "Describing EC2 security groups..."
aws ec2 describe-security-groups

echo "Describing public AMIs..."
aws ec2 describe-images \
  --owners amazon \
  --filters "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" \
  --query 'Images[*].[ImageId,Name]' \
  --output table \
  --region "$REGION"

# Cleanup note
echo "Note: Resources like policies and log groups created here should be cleaned up manually or by a teardown script."

# Caller identity confirmation
aws sts get-caller-identity
