#!/usr/bin/env python3
import hcl2
import os
import json
import sys
import boto3
import logging
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def validate_environment():
    """Validate required environment variables and AWS credentials."""
    required_vars = ["S3_BUCKET_NAME"]
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        sys.exit(1)
    
    try:
        boto3.client("sts").get_caller_identity()
    except NoCredentialsError:
        logger.error("AWS credentials not configured")
        sys.exit(1)

def collect_iam_resources(tf_folder, account_id):
    """Enhanced IAM resource collection with better error handling."""
    iam_resource_types = {
        "aws_iam_user": "user",
        "aws_iam_role": "role", 
        "aws_iam_group": "group",
        "aws_iam_policy": "policy",
        "aws_iam_role_policy_attachment": "role-policy-attachment",
        "aws_iam_user_policy_attachment": "user-policy-attachment",
        "aws_iam_group_policy_attachment": "group-policy-attachment",
        "aws_iam_role_policy": "inline-role-policy",
        "aws_iam_user_policy": "inline-user-policy",
        "aws_iam_group_policy": "inline-group-policy"
    }

    result = {rtype: [] for rtype in iam_resource_types}
    processed_files = 0
    error_files = 0

    for root, _, files in os.walk(tf_folder):
        for file in files:
            if file.endswith(".tf"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = hcl2.load(f)
                        resources = data.get("resource", [])

                        if isinstance(resources, dict):
                            resources = [resources]

                        for block in resources:
                            for res_type, res_defs in block.items():
                                if res_type in iam_resource_types:
                                    for tf_resource_name, resource_body in res_defs.items():
                                        name = resource_body.get("name", tf_resource_name)
                                        
                                        entry = {
                                            "tf_resource_name": tf_resource_name,
                                            "name": name,
                                            "type": iam_resource_types[res_type],
                                            "source_file": os.path.relpath(file_path, tf_folder)
                                        }

                                        if res_type in ["aws_iam_user", "aws_iam_role", "aws_iam_group"]:
                                            entry["arn"] = f"arn:aws:iam::{account_id}:{entry['type']}/{name}"

                                        result[res_type].append(entry)
                    
                    processed_files += 1
                    
                except Exception as e:
                    logger.warning(f"Error processing {file_path}: {str(e)}")
                    error_files += 1

    logger.info(f"Processed {processed_files} files successfully, {error_files} files with errors")
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.error("Usage: python3 parse_iam_tf.py <terraform_path>")
        sys.exit(1)
    
    validate_environment()
    
    tf_path = sys.argv[1]
    s3_bucket = os.environ.get("S3_BUCKET_NAME")
    s3_prefix = os.environ.get("S3_KEY_PREFIX", "iam-parsed")

    if not os.path.exists(tf_path):
        logger.error(f"Terraform path does not exist: {tf_path}")
        sys.exit(1)

    try:
        account_id = boto3.client("sts").get_caller_identity()["Account"]
        logger.info(f"Analyzing Terraform files in: {tf_path}")
        
        resources = collect_iam_resources(tf_path, account_id)
        
        # Add metadata
        output_data = {
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "terraform_path": tf_path,
                "account_id": account_id,
                "total_resources": sum(len(v) for v in resources.values())
            },
            "resources": resources
        }
        
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        key_versioned = f"{s3_prefix}/iam_resources_{timestamp}.json"
        key_latest = f"{s3_prefix}/latest.json"

        json_data = json.dumps(output_data, indent=2)

        s3 = boto3.client("s3")
        
        # Upload with proper error handling
        try:
            s3.put_object(
                Bucket=s3_bucket, 
                Key=key_versioned, 
                Body=json_data, 
                ContentType="application/json",
            )
            s3.put_object(
                Bucket=s3_bucket, 
                Key=key_latest, 
                Body=json_data, 
                ContentType="application/json",
            )
            
            logger.info(f"Successfully uploaded to s3://{s3_bucket}/{key_versioned}")
            logger.info(f"Successfully uploaded to s3://{s3_bucket}/{key_latest}")
            
        except ClientError as e:
            logger.error(f"Failed to upload to S3: {e}")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)