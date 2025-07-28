# step2_cloudtrail/index.py - Start CloudTrail Lake query with batching

import os
import boto3
import json
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def batch_users(user_arns, batch_size):
    """Split user ARNs into batches"""
    for i in range(0, len(user_arns), batch_size):
        yield user_arns[i:i + batch_size]

def start_cloudtrail_query(cloudtrail_client, user_arns_batch, event_data_store_arn, retention_days):
    """Start a CloudTrail query for a batch of users"""
    
    store_id = event_data_store_arn.split('/')[-1]
    arn_list = "', '".join(user_arns_batch)
    
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
    LIMIT 5000
    """
    
    response = cloudtrail_client.start_query(QueryStatement=query)
    return response['QueryId']

def lambda_handler(event, context):
    """Start CloudTrail Lake queries for user API usage with batching"""
    
    try:
        # Get environment variables
        event_data_store_arn = os.environ['CLOUDTRAIL_EVENT_DATA_STORE_ARN']
        retention_days = int(os.environ['CLOUDTRAIL_RETENTION_DAYS'])
        batch_size = int(os.environ.get('CLOUDTRAIL_BATCH_SIZE', '15'))
        
        # Get users from previous step
        users = event.get('users', [])
        if not users:
            raise Exception("No users provided from previous step")
        
        # Initialize CloudTrail client
        cloudtrail_client = boto3.client('cloudtrail')
        
        # Extract valid user ARNs (filter out template variables)
        user_arns = []
        filtered_arns = []
        
        for user in users:
            arn = user.get('arn', '')
            if '${' not in arn and arn.startswith('arn:aws:iam:'):
                user_arns.append(arn)
            else:
                filtered_arns.append(arn)
        
        if not user_arns:
            logger.warning("No valid user ARNs found")
            return {
                'statusCode': 200,
                'query_ids': [],
                'batch_info': {
                    'total_users': len(users),
                    'valid_users': 0,
                    'filtered_users': len(filtered_arns),
                    'batches_created': 0
                },
                'users': users,
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'roles': event.get('roles', [])
            }
        
        logger.info(f"Processing {len(user_arns)} valid users in batches of {batch_size}")
        logger.info(f"Filtered out {len(filtered_arns)} invalid ARNs")
        
        # Start queries for each batch
        query_ids = []
        batch_details = []
        
        for batch_num, user_batch in enumerate(batch_users(user_arns, batch_size), 1):
            try:
                query_id = start_cloudtrail_query(
                    cloudtrail_client, user_batch, event_data_store_arn, retention_days
                )
                
                batch_info = {
                    'batch_number': batch_num,
                    'query_id': query_id,
                    'user_arns': user_batch,
                    'user_count': len(user_batch)
                }
                
                query_ids.append(query_id)
                batch_details.append(batch_info)
                
                logger.info(f"Started batch {batch_num} query: {query_id} ({len(user_batch)} users)")
                
            except Exception as batch_error:
                logger.error(f"Failed to start batch {batch_num}: {batch_error}")
                # Continue with other batches
                batch_info = {
                    'batch_number': batch_num,
                    'query_id': None,
                    'error': str(batch_error),
                    'user_arns': user_batch,
                    'user_count': len(user_batch)
                }
                batch_details.append(batch_info)
        
        successful_queries = [q for q in query_ids if q]
        
        logger.info(f"Started {len(successful_queries)} CloudTrail queries across {len(batch_details)} batches")
        
        return {
            'statusCode': 200,
            'query_ids': query_ids,
            'batch_details': batch_details,
            'batch_info': {
                'total_users': len(users),
                'valid_users': len(user_arns),
                'filtered_users': len(filtered_arns),
                'batches_created': len(batch_details),
                'successful_queries': len(successful_queries),
                'batch_size': batch_size
            },
            'users': users,
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': {
                'retention_days': retention_days,
                'user_count': len(user_arns),
                'event_data_store_arn': event_data_store_arn
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