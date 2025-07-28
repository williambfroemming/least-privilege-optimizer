# step2_cloudtrail/index.py - Start CloudTrail Lake query

import os
import boto3
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Start CloudTrail Lake query for user API usage"""
    
    try:
        # Get environment variables
        event_data_store_arn = os.environ['CLOUDTRAIL_EVENT_DATA_STORE_ARN']
        retention_days = int(os.environ['CLOUDTRAIL_RETENTION_DAYS'])
        
        # Get users from previous step
        users = event.get('users', [])
        if not users:
            raise Exception("No users provided from previous step")
        
        # Initialize CloudTrail client
        cloudtrail_client = boto3.client('cloudtrail')
        
        # Extract valid user ARNs (filter out template variables)
        user_arns = []
        for user in users:
            arn = user.get('arn', '')
            if '${' not in arn and arn.startswith('arn:aws:iam:'):
                user_arns.append(arn)
        
        if not user_arns:
            logger.warning("No valid user ARNs found")
            return {
                'statusCode': 200,
                'query_id': 'no-valid-arns',
                'users': users,
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'roles': event.get('roles', [])
            }
        
        # Build CloudTrail query
        store_id = event_data_store_arn.split('/')[-1]
        arn_list = "', '".join(user_arns)
        
        query = f"""
        SELECT 
            userIdentity.arn as principal_arn,
            eventName,
            eventSource,
            COUNT(*) as call_count
        FROM {store_id}
        WHERE 
            eventTime >= now() - interval '{retention_days}' day
            AND userIdentity.arn IN ('{arn_list}')
            AND userIdentity.arn IS NOT NULL
            AND errorCode IS NULL
            AND eventName != 'AssumeRole'
            AND eventName != 'GetSessionToken'
        GROUP BY 
            userIdentity.arn, eventName, eventSource
        ORDER BY 
            principal_arn, call_count DESC
        LIMIT 1000
        """
        
        logger.info(f"Starting CloudTrail query for {len(user_arns)} users")
        
        # Start the query
        response = cloudtrail_client.start_query(QueryStatement=query)
        query_id = response['QueryId']
        
        logger.info(f"Started query: {query_id}")
        
        return {
            'statusCode': 200,
            'query_id': query_id,
            'users': users,
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': {
                'retention_days': retention_days,
                'user_count': len(user_arns)
            }
        }
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return {
            'statusCode': 500,
            'error': str(e),
            'users': event.get('users', []),
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', [])
        }