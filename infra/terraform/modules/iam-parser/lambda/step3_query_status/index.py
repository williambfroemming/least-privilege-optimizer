# step3_query_status/index.py - Check multiple CloudTrail query statuses and aggregate results

import boto3
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def process_query_results(cloudtrail_client, query_id):
    """Process results from a single CloudTrail query"""
    try:
        results_response = cloudtrail_client.get_query_results(QueryId=query_id)
        query_results = results_response.get('QueryResultRows', [])
        
        processed_results = []
        for row in query_results:
            result = {}
            for col_dict in row:
                for key, value in col_dict.items():
                    result[key] = value
            processed_results.append(result)
        
        return processed_results, results_response.get('QueryStatistics', {})
    
    except Exception as e:
        logger.error(f"Failed to get results for query {query_id}: {e}")
        return [], {}

def aggregate_user_api_usage(all_results, users):
    """Aggregate API usage results by user"""
    user_api_usage = {}
    arn_to_name = {user['arn']: user['name'] for user in users}
    
    for result in all_results:
        try:
            user_arn = result.get('principal_arn', '')
            event_name = result.get('eventName', '')
            event_source = result.get('eventSource', '')
            call_count = int(result.get('call_count', 0))
            
            if user_arn in arn_to_name:
                user_name = arn_to_name[user_arn]
                
                if user_name not in user_api_usage:
                    user_api_usage[user_name] = {}
                
                # Convert to IAM action format
                service = event_source.replace('.amazonaws.com', '')
                iam_action = f"{service}:{event_name}"
                
                # Store with call count for analysis
                if iam_action in user_api_usage[user_name]:
                    user_api_usage[user_name][iam_action] += call_count
                else:
                    user_api_usage[user_name][iam_action] = call_count
                    
        except (ValueError, TypeError) as e:
            logger.warning(f"Error processing result {result}: {e}")
            continue
    
    return user_api_usage

def lambda_handler(event, context):
    """Check CloudTrail query statuses and aggregate results"""
    
    try:
        # Handle both single query_id (backward compatibility) and multiple query_ids
        query_ids = event.get('query_ids', [])
        single_query_id = event.get('query_id')
        
        if single_query_id and not query_ids:
            query_ids = [single_query_id]
        
        if not query_ids:
            raise Exception("No query_ids provided")
        
        users = event.get('users', [])
        batch_details = event.get('batch_details', [])
        
        # Handle mock/invalid query IDs
        mock_queries = [q for q in query_ids if q in ['no-valid-arns'] or (q and q.startswith('mock-'))]
        if mock_queries:
            logger.info(f"Found {len(mock_queries)} mock query IDs")
            return {
                'statusCode': 200,
                'query_status': 'FINISHED',
                'completed_queries': mock_queries,
                'failed_queries': [],
                'running_queries': [],
                'user_api_usage': {},
                'total_results_count': 0,
                'users': users,
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'roles': event.get('roles', []),
                'query_details': event.get('query_details', {}),
                'batch_details': batch_details
            }
        
        # Filter out None/empty query IDs
        valid_query_ids = [q for q in query_ids if q]
        
        if not valid_query_ids:
            logger.warning("No valid query IDs found")
            return {
                'statusCode': 200,
                'query_status': 'FINISHED',
                'completed_queries': [],
                'failed_queries': [],
                'running_queries': [],
                'user_api_usage': {},
                'total_results_count': 0,
                'users': users,
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'roles': event.get('roles', []),
                'query_details': event.get('query_details', {}),
                'batch_details': batch_details
            }
        
        # Initialize CloudTrail client
        cloudtrail_client = boto3.client('cloudtrail')
        
        # Check status of all queries
        completed_queries = []
        failed_queries = []
        running_queries = []
        all_results = []
        total_stats = {'ResultsCount': 0, 'BytesScanned': 0}
        
        for query_id in valid_query_ids:
            try:
                response = cloudtrail_client.describe_query(QueryId=query_id)
                query_status = response['QueryStatus']
                
                logger.info(f"Query {query_id}: {query_status}")
                
                if query_status == 'FINISHED':
                    completed_queries.append(query_id)
                    # Get results immediately
                    results, stats = process_query_results(cloudtrail_client, query_id)
                    all_results.extend(results)
                    
                    # Aggregate stats
                    total_stats['ResultsCount'] += stats.get('ResultsCount', 0)
                    total_stats['BytesScanned'] += stats.get('BytesScanned', 0)
                    
                elif query_status == 'FAILED':
                    error_message = response.get('ErrorMessage', 'Unknown error')
                    failed_queries.append({'query_id': query_id, 'error': error_message})
                    logger.error(f"Query {query_id} failed: {error_message}")
                    
                else:
                    running_queries.append(query_id)
                    
            except Exception as e:
                logger.error(f"Failed to check query {query_id}: {e}")
                failed_queries.append({'query_id': query_id, 'error': str(e)})
        
        # Determine overall status
        if running_queries:
            overall_status = 'RUNNING'
            status_code = 202
            logger.info(f"{len(running_queries)} queries still running")
        elif failed_queries and not completed_queries:
            overall_status = 'FAILED'
            status_code = 500
        else:
            overall_status = 'FINISHED'
            status_code = 200
            
        # Process results if we have any completed queries
        user_api_usage = {}
        if all_results:
            user_api_usage = aggregate_user_api_usage(all_results, users)
            logger.info(f"Processed {len(all_results)} total results for {len(user_api_usage)} users")
        
        return {
            'statusCode': status_code,
            'query_status': overall_status,
            'completed_queries': completed_queries,
            'failed_queries': failed_queries,
            'running_queries': running_queries,
            'query_summary': {
                'total_queries': len(valid_query_ids),
                'completed': len(completed_queries),
                'failed': len(failed_queries),
                'running': len(running_queries)
            },
            'user_api_usage': user_api_usage,
            'total_results_count': len(all_results),
            'query_statistics': total_stats,
            'users': users,
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {}),
            'batch_details': batch_details
        }
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return {
            'statusCode': 500,
            'error': str(e),
            'query_status': 'FAILED',
            'completed_queries': [],
            'failed_queries': [],
            'running_queries': [],
            'user_api_usage': {},
            'total_results_count': 0,
            'users': event.get('users', []),
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {}),
            'batch_details': event.get('batch_details', [])
        }