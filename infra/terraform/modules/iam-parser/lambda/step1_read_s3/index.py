# step1_read_s3/index.py - Read IAM data from S3

import json
import os
import boto3
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Read IAM data from S3 and extract users/roles"""
    
    try:
        # Get environment variables
        bucket_name = os.environ['S3_BUCKET']
        s3_prefix = os.environ.get('S3_PREFIX', '')
        
        # Initialize S3 client
        s3_client = boto3.client('s3')
        
        # Construct S3 key
        s3_key = f"{s3_prefix}/latest.json" if s3_prefix else "latest.json"
        
        logger.info(f"Reading from s3://{bucket_name}/{s3_key}")
        
        # Read the file
        response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
        content = response['Body'].read().decode('utf-8')
        iam_data = json.loads(content)
        
        # Extract users
        users = []
        for user in iam_data['resources'].get('aws_iam_user', []):
            users.append({
                'name': user['name'],
                'arn': user['arn'],
                'tf_resource_name': user['tf_resource_name'],
                'source_file': user['source_file']
            })
        
        # Extract roles
        roles = []
        for role in iam_data['resources'].get('aws_iam_role', []):
            roles.append({
                'name': role['name'],
                'arn': role['arn'],
                'tf_resource_name': role['tf_resource_name'],
                'source_file': role['source_file']
            })
        
        logger.info(f"Found {len(users)} users and {len(roles)} roles")
        
        return {
            'statusCode': 200,
            'iam_data': iam_data,
            'users': users,
            'roles': roles,
            'metadata': {
                'timestamp': iam_data['metadata']['timestamp'],
                'account_id': iam_data['metadata']['account_id'],
                'users_count': len(users),
                'roles_count': len(roles)
            }
        }
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return {
            'statusCode': 500,
            'error': str(e)
        }