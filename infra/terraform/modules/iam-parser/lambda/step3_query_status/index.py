# step3_query_status/index.py - Check CloudTrail query status and get results

import boto3
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Check CloudTrail query status and get results if completed"""
    
    try:
        # Get query ID from previous step
        query_id = event.get('query_id')
        users = event.get('users', [])
        
        if not query_id:
            raise Exception("No query_id provided")
        
        # Handle mock/invalid query IDs
        if query_id in ['no-valid-arns'] or query_id.startswith('mock-'):
            logger.info(f"Mock query ID: {query_id}")
            return {
                'statusCode': 200,
                'query_status': 'FINISHED',
                'query_id': query_id,
                'user_api_usage': {},
                'query_results_count': 0,
                'users': users,
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'roles': event.get('roles', []),
                'query_details': event.get('query_details', {})
            }
        
        # Initialize CloudTrail client
        cloudtrail_client = boto3.client('cloudtrail')
        
        # Check query status
        try:
            response = cloudtrail_client.describe_query(QueryId=query_id)
            query_status = response['QueryStatus']
            
            logger.info(f"Query status: {query_status}")
            
        except Exception as e:
            logger.error(f"Failed to describe query: {e}")
            # Return finished status with empty results for now
            return {
                'statusCode': 200,
                'query_status': 'FINISHED',
                'query_id': query_id,
                'user_api_usage': {},
                'query_results_count': 0,
                'users': users,
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'roles': event.get('roles', []),
                'query_details': event.get('query_details', {}),
                'note': 'Query describe failed - using empty results'
            }
        
        if query_status == 'FINISHED':
            # Get results
            try:
                results_response = cloudtrail_client.get_query_results(QueryId=query_id)
                query_results = results_response.get('QueryResultRows', [])
                
                logger.info(f"Retrieved {len(query_results)} query result rows")
                
                # Process results into user API usage
                user_api_usage = {}
                arn_to_name = {user['arn']: user['name'] for user in users}
                
                # Skip header row if present
                data_rows = query_results[1:] if query_results and len(query_results) > 1 else query_results
                
                for row in data_rows:
                    if len(row) >= 3:
                        try:
                            user_arn = str(row[0])  # principal_arn - ensure it's a string
                            event_name = str(row[1])  # event_name - ensure it's a string
                            event_source = str(row[2])  # event_source - ensure it's a string
                            
                            if user_arn in arn_to_name:
                                user_name = arn_to_name[user_arn]
                                
                                if user_name not in user_api_usage:
                                    user_api_usage[user_name] = []
                                
                                # Convert to IAM action format
                                service = event_source.replace('.amazonaws.com', '')
                                iam_action = f"{service}:{event_name}"
                                
                                if iam_action not in user_api_usage[user_name]:
                                    user_api_usage[user_name].append(iam_action)
                        except (TypeError, AttributeError) as e:
                            logger.warning(f"Error processing row {row}: {e}")
                            continue
                
                logger.info(f"Processed {len(query_results)} results for {len(user_api_usage)} users")
                
                return {
                    'statusCode': 200,
                    'query_status': 'FINISHED',
                    'query_id': query_id,
                    'user_api_usage': user_api_usage,
                    'query_results_count': len(query_results),
                    'users': users,
                    'metadata': event.get('metadata', {}),
                    'iam_data': event.get('iam_data', {}),
                    'roles': event.get('roles', []),
                    'query_details': event.get('query_details', {})
                }
                
            except Exception as e:
                logger.error(f"Failed to get query results: {e}")
                # Return with empty results but successful status
                return {
                    'statusCode': 200,
                    'query_status': 'FINISHED',
                    'query_id': query_id,
                    'user_api_usage': {},
                    'query_results_count': 0,
                    'users': users,
                    'metadata': event.get('metadata', {}),
                    'iam_data': event.get('iam_data', {}),
                    'roles': event.get('roles', []),
                    'query_details': event.get('query_details', {}),
                    'note': 'Query results failed - using empty results'
                }
            
        elif query_status == 'FAILED':
            error_message = response.get('ErrorMessage', 'Unknown error')
            raise Exception(f"CloudTrail query failed: {error_message}")
            
        else:
            # Still running
            return {
                'statusCode': 202,
                'query_status': query_status,
                'query_id': query_id,
                'message': f"Query still {query_status.lower()}",
                'query_results_count': 0,
                'users': users,
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'roles': event.get('roles', []),
                'query_details': event.get('query_details', {})
            }
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return {
            'statusCode': 500,
            'error': str(e),
            'query_status': 'FAILED',  # Add this so Step Function can handle it
            'query_results_count': 0,
            'users': event.get('users', []),
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {})
        }