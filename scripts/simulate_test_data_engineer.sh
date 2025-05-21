#!/bin/bash

# --- CONFIGURATION ---
ROLE_ARN="arn:aws:iam::<AWS ACCOUNT NUMBER>:role/test-data-engineer" # Replace with your aws account number
SESSION_NAME="simulate-test-data-engineer"
BUCKET_NAME="ucb-capstone-bucket"
ATHENA_RESULTS_BUCKET="s3://ucb-capstone-athena-results/athena-results/"
ATHENA_QUERY="SELECT * FROM sampledb.elb_logs LIMIT 10;"  # Replace with valid table
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

echo "✅ Temporary credentials exported."

# --- S3 Operations ---
echo "Uploading file to S3..."
echo "hello world" > test.csv
aws s3 cp test.csv s3://$BUCKET_NAME/test.csv

echo "Listing bucket contents..."
aws s3 ls s3://$BUCKET_NAME/

echo "Removing test file from S3..."
aws s3 rm s3://$BUCKET_NAME/test.csv

# --- Athena Query ---
echo "Submitting Athena query..."
aws athena start-query-execution \
  --query-string "$ATHENA_QUERY" \
  --result-configuration OutputLocation="$ATHENA_RESULTS_BUCKET" \
  --region "$REGION"

# --- Glue Queries ---
echo "Getting Glue databases..."
aws glue get-databases

echo "Getting Glue tables in 'default' database..."
aws glue get-tables --database-name default

# --- CloudWatch Logs ---
echo "Describing CloudWatch log groups..."
aws logs describe-log-groups

# --- EC2 Describe ---
echo "Describing EC2 instances..."
aws ec2 describe-instances --region "$REGION"

# --- Done ---
echo "Simulation complete. You are still operating as: $(aws sts get-caller-identity | jq -r .Arn)"
