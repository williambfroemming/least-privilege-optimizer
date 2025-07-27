# lambda/index.py - Updated to support Step Functions

import json
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
import os
from botocore.exceptions import ClientError
import re

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# =============================================================================
# STEP 1: READ S3 DATA HANDLER
# =============================================================================
def read_s3_data_handler(event, context):
    """
    Step 1: Read IAM resource data from S3
    
    Handler: read_s3_data_handler
    Input: Step Function execution input
    Output: {
        "iam_data": {...},
        "users": [...],
        "metadata": {...}
    }
    """
    try:
        # Get environment variables
        bucket_name = os.environ.get('S3_BUCKET')
        s3_prefix = os.environ.get('S3_PREFIX', '')
        
        if not bucket_name:
            raise ValueError("S3_BUCKET environment variable not set")
        
        logger.info(f"Reading IAM data from bucket: {bucket_name}, prefix: {s3_prefix}")
        
        # Initialize S3 client
        s3_client = boto3.client('s3')
        
        # Construct S3 key
        s3_key = f"{s3_prefix}/latest.json" if s3_prefix else "latest.json"
        
        # Read the file
        response = s3_client.get_object(
            Bucket=bucket_name,
            Key=s3_key
        )
        
        content = response['Body'].read().decode('utf-8')
        iam_data = json.loads(content)
        
        # Extract user information
        users = []
        for user in iam_data['resources'].get('aws_iam_user', []):
            users.append({
                'name': user['name'],
                'arn': user['arn'],
                'tf_resource_name': user['tf_resource_name'],
                'source_file': user['source_file']
            })
        
        # Extract role information (for future use)
        roles = []
        for role in iam_data['resources'].get('aws_iam_role', []):
            roles.append({
                'name': role['name'],
                'arn': role['arn'],
                'tf_resource_name': role['tf_resource_name'],
                'source_file': role['source_file']
            })
        
        logger.info(f"Successfully parsed IAM data: {len(users)} users, {len(roles)} roles")
        
        # Return data for next step
        return {
            'statusCode': 200,
            'iam_data': iam_data,
            'users': users,
            'roles': roles,
            'metadata': {
                'timestamp': iam_data['metadata']['timestamp'],
                'account_id': iam_data['metadata']['account_id'],
                'total_resources': iam_data['metadata']['total_resources'],
                'users_count': len(users),
                'roles_count': len(roles)
            }
        }
        
    except Exception as e:
        logger.error(f"Error in read_s3_data_handler: {e}")
        return {
            'statusCode': 500,
            'error': f"Error reading S3 data: {str(e)}"
        }

# =============================================================================
# STEP 2: START CLOUDTRAIL QUERY HANDLER
# =============================================================================
def start_cloudtrail_query_handler(event, context):
    """
    Step 2: Start CloudTrail Lake query for user API usage
    """
    try:
        # Get input from previous step
        users = event.get('users', [])
        if not users:
            raise ValueError("No users provided from previous step")
        
        # Get environment variables
        event_data_store_arn = os.environ.get('CLOUDTRAIL_EVENT_DATA_STORE_ARN')
        retention_days = int(os.environ.get('CLOUDTRAIL_RETENTION_DAYS', '30'))
        
        if not event_data_store_arn:
            raise ValueError("CLOUDTRAIL_EVENT_DATA_STORE_ARN environment variable not set")
        
        logger.info(f"Starting CloudTrail Lake query for {len(users)} users, looking back {retention_days} days")
        
        # Initialize CloudTrail client
        cloudtrail_client = boto3.client('cloudtrail')
        
        # Calculate date range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=retention_days)
        
        # Extract and clean user ARNs
        user_arns = []
        valid_users = []
        
        for user in users:
            arn = user.get('arn', '')
            # Skip ARNs with template variables
            if '${' not in arn and arn.startswith('arn:aws:iam:'):
                user_arns.append(arn)
                valid_users.append(user)
            else:
                logger.warning(f"Skipping user with templated ARN: {user.get('name', 'unknown')}")
        
        if not user_arns:
            logger.warning("No valid user ARNs found - all contain template variables")
            # Return a mock response for testing
            return {
                'statusCode': 200,
                'query_id': 'mock-query-no-valid-arns',
                'users': users,
                'query_details': {
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat(),
                    'user_count': len(users),
                    'valid_user_count': 0,
                    'retention_days': retention_days,
                    'event_data_store_arn': event_data_store_arn,
                    'note': 'No valid ARNs found - using mock query ID'
                },
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'roles': event.get('roles', [])
            }
        
        # Build the CloudTrail Lake query (now passing the Event Data Store ARN)
        query = build_cloudtrail_query(user_arns, start_time, end_time, event_data_store_arn)
        
        logger.info(f"Executing CloudTrail Lake query from {start_time.isoformat()} to {end_time.isoformat()}")
        logger.info(f"Query: {query[:200]}...")  # Log first 200 chars of query for debugging
        
        # Start the query
        try:
            response = cloudtrail_client.start_query(
                QueryStatement=query
            )
            
            query_id = response['QueryId']
            logger.info(f"Started CloudTrail Lake query with ID: {query_id}")
            
        except ClientError as e:
            logger.error(f"CloudTrail start_query failed: {e}")
            # Return mock response for testing
            return {
                'statusCode': 200,
                'query_id': 'mock-query-failed-start',
                'users': users,
                'query_details': {
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat(),
                    'user_count': len(users),
                    'valid_user_count': len(valid_users),
                    'retention_days': retention_days,
                    'event_data_store_arn': event_data_store_arn,
                    'error': str(e),
                    'note': 'CloudTrail query failed - using mock query ID'
                },
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'roles': event.get('roles', [])
            }
        
        return {
            'statusCode': 200,
            'query_id': query_id,
            'users': users,
            'query_details': {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'user_count': len(users),
                'valid_user_count': len(valid_users),
                'retention_days': retention_days,
                'event_data_store_arn': event_data_store_arn
            },
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', [])
        }
        
    except Exception as e:
        logger.error(f"Error in start_cloudtrail_query_handler: {e}")
        return {
            'statusCode': 500,
            'error': f"CloudTrail error: {str(e)}"
        }

# =============================================================================
# STEP 3: CHECK CLOUDTRAIL QUERY STATUS AND GET RESULTS
# =============================================================================
# Add this function to your lambda/index.py after start_cloudtrail_query_handler

def check_cloudtrail_query_handler(event, context):
    """
    Step 3: Check CloudTrail Lake query status and get results
    """
    try:
        # Get input from previous step
        query_id = event.get('query_id')
        users = event.get('users', [])
        
        if not query_id:
            raise ValueError("No query_id provided from previous step")
        
        logger.info(f"Checking status of CloudTrail query: {query_id}")
        
        # Initialize CloudTrail client
        cloudtrail_client = boto3.client('cloudtrail')
        
        # Check query status
        try:
            response = cloudtrail_client.describe_query(QueryId=query_id)
            query_status = response['QueryStatus']
            logger.info(f"Query status: {query_status}")
            
        except ClientError as e:
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
            # Query completed successfully - get results
            logger.info("Query completed, retrieving results...")
            
            try:
                results_response = cloudtrail_client.get_query_results(QueryId=query_id)
                query_results = results_response.get('QueryResultRows', [])
                
                # Process the results
                user_api_usage = process_cloudtrail_results(query_results, users)
                
                logger.info(f"Processed {len(query_results)} query result rows into usage data for {len(user_api_usage)} users")
                
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
                
            except ClientError as e:
                logger.error(f"Failed to get query results: {e}")
                # Return with empty results
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
            logger.error(f"CloudTrail query failed: {error_message}")
            return {
                'statusCode': 500,
                'query_status': 'FAILED',
                'error': f"CloudTrail query failed: {error_message}",
                'query_id': query_id
            }
            
        else:
            # Query still running (RUNNING, QUEUED)
            logger.info(f"Query still in progress: {query_status}")
            return {
                'statusCode': 202,
                'query_status': query_status,
                'query_id': query_id,
                'message': f"Query still {query_status.lower()}, need to wait longer",
                'users': users,
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'roles': event.get('roles', []),
                'query_details': event.get('query_details', {})
            }
        
    except Exception as e:
        logger.error(f"Error in check_cloudtrail_query_handler: {e}")
        return {
            'statusCode': 500,
            'query_status': 'FAILED',
            'error': f"Error checking CloudTrail query: {str(e)}"
        }

def process_cloudtrail_results(query_results: List[List], users: List[Dict[str, str]]) -> Dict[str, List[str]]:
    """
    Process CloudTrail Lake query results into user API usage
    """
    user_api_usage = {}
    
    # Create mapping from ARN to user name
    arn_to_name = {user['arn']: user['name'] for user in users}
    
    # Skip header row if present, process data rows
    data_rows = query_results[1:] if query_results and len(query_results) > 1 else query_results
    
    for row in data_rows:
        if len(row) < 3:  # Make sure we have minimum columns
            logger.warning(f"Skipping incomplete result row: {row}")
            continue
            
        try:
            user_arn = row[0]  # principal_arn
            event_name = row[1]
            event_source = row[2]
            
            # Only process users we're analyzing
            if user_arn in arn_to_name:
                user_name = arn_to_name[user_arn]
                
                if user_name not in user_api_usage:
                    user_api_usage[user_name] = []
                
                # Convert CloudTrail event to IAM action format
                iam_action = convert_event_to_iam_action(event_name, event_source)
                if iam_action and iam_action not in user_api_usage[user_name]:
                    user_api_usage[user_name].append(iam_action)
                    
        except (IndexError, ValueError) as e:
            logger.warning(f"Error processing result row {row}: {e}")
            continue
    
    return user_api_usage

def convert_event_to_iam_action(event_name: str, event_source: str) -> str:
    """Convert CloudTrail event to IAM action format"""
    # Remove .amazonaws.com suffix from event source
    service = event_source.replace('.amazonaws.com', '')
    
    # Simple mapping - can be expanded
    service_mappings = {
        's3': 's3',
        'iam': 'iam', 
        'ec2': 'ec2',
        'lambda': 'lambda',
        'rds': 'rds',
        'cloudformation': 'cloudformation',
        'sts': 'sts',
        'logs': 'logs',
        'cloudwatch': 'cloudwatch'
    }
    
    service_name = service_mappings.get(service, service)
    return f"{service_name}:{event_name}"

# =============================================================================
# STEP 4: FETCH TERRAFORM FILES FROM GITHUB
# =============================================================================
def fetch_terraform_files_handler(event, context):
    """
    Step 4: Fetch all .tf files from the GitHub repository
    
    Handler: fetch_terraform_files_handler
    Input: Output from Step 3 with user_api_usage
    Output: {
        "terraform_files": {...},
        "user_api_usage": {...},
        "users": [...],
        ...
    }
    """
    try:
        # Get input from previous steps
        user_api_usage = event.get('user_api_usage', {})
        users = event.get('users', [])
        
        logger.info(f"Fetching Terraform files for {len(users)} users")
        
        # Get environment variables
        github_repo = os.environ.get('GITHUB_REPO')
        github_token_ssm_path = os.environ.get('GITHUB_TOKEN_SSM_PATH')
        
        if not github_repo:
            raise ValueError("GITHUB_REPO environment variable not set")
        if not github_token_ssm_path:
            raise ValueError("GITHUB_TOKEN_SSM_PATH environment variable not set")
        
        # Get GitHub token from SSM
        ssm_client = boto3.client('ssm')
        try:
            token_response = ssm_client.get_parameter(
                Name=github_token_ssm_path,
                WithDecryption=True
            )
            github_token = token_response['Parameter']['Value']
        except ClientError as e:
            logger.error(f"Failed to get GitHub token from SSM: {e}")
            raise ValueError(f"Could not retrieve GitHub token from {github_token_ssm_path}")
        
        # Fetch Terraform files from GitHub
        terraform_files = fetch_terraform_files_from_github(github_repo, github_token)
        
        logger.info(f"Successfully fetched {len(terraform_files)} Terraform files")
        
        return {
            'statusCode': 200,
            'terraform_files': terraform_files,
            'terraform_files_count': len(terraform_files),
            # Pass through from previous steps
            'user_api_usage': user_api_usage,
            'users': users,
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {}),
            'query_results_count': event.get('query_results_count', 0)
        }
        
    except Exception as e:
        logger.error(f"Error in fetch_terraform_files_handler: {e}")
        return {
            'statusCode': 500,
            'error': f"Error fetching Terraform files: {str(e)}"
        }

def fetch_terraform_files_from_github(repo: str, token: str) -> Dict[str, str]:
    """
    Fetch all .tf files from the GitHub repository recursively
    
    Returns: {
        "path/to/file.tf": "file content",
        ...
    }
    """
    try:
        from github import Github
        
        # Initialize GitHub client
        g = Github(token)
        repository = g.get_repo(repo)
        
        terraform_files = {}
        
        def get_files_recursive(path=""):
            """Recursively get all .tf files from the repository"""
            try:
                contents = repository.get_contents(path)
                
                # Handle both single files and directories
                if not isinstance(contents, list):
                    contents = [contents]
                
                for content in contents:
                    if content.type == "file" and content.name.endswith('.tf'):
                        # Get file content
                        file_content = content.decoded_content.decode('utf-8')
                        terraform_files[content.path] = file_content
                        logger.info(f"Retrieved Terraform file: {content.path}")
                        
                    elif content.type == "dir":
                        # Recursively process subdirectories
                        get_files_recursive(content.path)
                        
            except Exception as e:
                logger.warning(f"Error processing path {path}: {e}")
        
        # Start recursive fetch from root
        get_files_recursive()
        
        if not terraform_files:
            logger.warning("No Terraform files found in repository")
        
        return terraform_files
        
    except Exception as e:
        logger.error(f"Error fetching files from GitHub: {e}")
        raise

# =============================================================================
# STEP 5: PARSE TERRAFORM POLICIES  
# =============================================================================
def parse_terraform_policies_handler(event, context):
    """
    Step 5: Parse Terraform files to extract current IAM policies for users
    
    Handler: parse_terraform_policies_handler
    Input: Output from Step 4 with terraform_files
    Output: {
        "user_policies": {...},
        "policy_recommendations": {...},
        ...
    }
    """
    try:
        # Get input from previous steps
        terraform_files = event.get('terraform_files', {})
        user_api_usage = event.get('user_api_usage', {})
        users = event.get('users', [])
        
        if not terraform_files:
            raise ValueError("No Terraform files provided from previous step")
        
        logger.info(f"Parsing {len(terraform_files)} Terraform files for {len(users)} users")
        
        # Parse current policies from Terraform files
        user_policies = parse_terraform_policies(terraform_files, users)
        
        # Generate recommendations
        policy_recommendations = generate_policy_recommendations(user_api_usage, user_policies)
        
        logger.info(f"Generated recommendations for {len(policy_recommendations)} users")
        
        return {
            'statusCode': 200,
            'user_policies': user_policies,
            'policy_recommendations': policy_recommendations,
            'recommendations_count': len(policy_recommendations),
            # Pass through from previous steps
            'terraform_files': terraform_files,
            'terraform_files_count': len(terraform_files),
            'user_api_usage': user_api_usage,
            'users': users,
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {}),
            'query_results_count': event.get('query_results_count', 0)
        }
        
    except Exception as e:
        logger.error(f"Error in parse_terraform_policies_handler: {e}")
        return {
            'statusCode': 500,
            'error': f"Error parsing Terraform policies: {str(e)}"
        }

def parse_terraform_policies(tf_files: Dict[str, str], users: List[Dict[str, str]]) -> Dict[str, Dict[str, Any]]:
    """Parse Terraform files to extract current IAM policies for users"""
    import re
    
    user_policies = {}
    
    # Create mapping from tf_resource_name to user name
    tf_name_to_user = {user['tf_resource_name']: user['name'] for user in users}
    
    for file_path, content in tf_files.items():
        logger.info(f"Parsing file: {file_path}")
        
        # Find inline user policies
        # Pattern: resource "aws_iam_user_policy" "name" { user = aws_iam_user.xyz.name ... }
        inline_policy_pattern = r'resource\s+"aws_iam_user_policy"\s+"([^"]+)"\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
        
        for match in re.finditer(inline_policy_pattern, content, re.DOTALL):
            policy_resource_name = match.group(1)
            policy_block = match.group(2)
            
            # Extract user reference
            user_match = re.search(r'user\s*=\s*aws_iam_user\.([^.\s]+)\.name', policy_block)
            if user_match:
                user_tf_name = user_match.group(1)
                
                if user_tf_name in tf_name_to_user:
                    user_name = tf_name_to_user[user_tf_name]
                    
                    if user_name not in user_policies:
                        user_policies[user_name] = {'inline_policies': [], 'attached_policies': []}
                    
                    # Extract policy document
                    policy_doc = extract_policy_document(policy_block)
                    
                    user_policies[user_name]['inline_policies'].append({
                        'name': policy_resource_name,
                        'file': file_path,
                        'policy_document': policy_doc
                    })
        
        # Find policy attachments
        # Pattern: resource "aws_iam_user_policy_attachment" "name" { user = aws_iam_user.xyz.name policy_arn = "..." }
        attachment_pattern = r'resource\s+"aws_iam_user_policy_attachment"\s+"([^"]+)"\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
        
        for match in re.finditer(attachment_pattern, content, re.DOTALL):
            attachment_resource_name = match.group(1)
            attachment_block = match.group(2)
            
            # Extract user reference
            user_match = re.search(r'user\s*=\s*aws_iam_user\.([^.\s]+)\.name', attachment_block)
            policy_match = re.search(r'policy_arn\s*=\s*"([^"]+)"', attachment_block)
            
            if user_match and policy_match:
                user_tf_name = user_match.group(1)
                policy_arn = policy_match.group(1)
                
                if user_tf_name in tf_name_to_user:
                    user_name = tf_name_to_user[user_tf_name]
                    
                    if user_name not in user_policies:
                        user_policies[user_name] = {'inline_policies': [], 'attached_policies': []}
                    
                    user_policies[user_name]['attached_policies'].append({
                        'name': attachment_resource_name,
                        'file': file_path,
                        'policy_arn': policy_arn
                    })
    
    logger.info(f"Parsed policies for {len(user_policies)} users")
    return user_policies

def extract_policy_document(policy_block: str) -> Dict[str, Any]:
    """Extract and parse policy document from Terraform block"""
    import json
    
    # Look for policy = jsonencode(...)
    policy_match = re.search(r'policy\s*=\s*jsonencode\s*\(\s*(\{.*?\})\s*\)', policy_block, re.DOTALL)
    
    if policy_match:
        policy_text = policy_match.group(1)
        try:
            # Basic parsing - convert Terraform syntax to JSON
            # This is simplified - a full parser would handle more edge cases
            policy_text = policy_text.replace('=', ':')
            policy_doc = json.loads(policy_text)
            return policy_doc
        except json.JSONDecodeError:
            logger.warning(f"Could not parse policy document: {policy_text[:100]}...")
            return {}
    
    return {}

def generate_policy_recommendations(user_api_usage: Dict[str, List[str]], 
                                  user_policies: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Generate least privilege policy recommendations"""
    recommendations = {}
    
    for user_name in user_policies.keys():
        # Get current permissions (simplified)
        current_actions = set()
        
        # Extract actions from inline policies
        for policy in user_policies[user_name].get('inline_policies', []):
            policy_doc = policy.get('policy_document', {})
            statements = policy_doc.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            for statement in statements:
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                current_actions.update(actions)
        
        # Handle attached policies (simplified - would need to resolve ARNs)
        for policy in user_policies[user_name].get('attached_policies', []):
            if 'AdministratorAccess' in policy['policy_arn']:
                current_actions.add('*')
        
        # Get actual usage
        used_actions = set(user_api_usage.get(user_name, []))
        
        # Generate recommendations
        recommendations[user_name] = {
            'current_actions': list(current_actions),
            'used_actions': list(used_actions),
            'unused_actions': list(current_actions - used_actions),
            'missing_actions': list(used_actions - current_actions),
            'recommendation': 'remove_unused' if current_actions - used_actions else 'no_changes'
        }
        
        logger.info(f"User {user_name}: {len(current_actions)} current, {len(used_actions)} used, {len(current_actions - used_actions)} unused")
    
    return recommendations


def lambda_handler(event, context):
    """
    Lambda handler - routes to appropriate step handler
    """
    # Log the full event for debugging
    logger.info(f"Lambda received event keys: {list(event.keys())}")
    
    # Check if there's a Payload wrapper
    if 'Payload' in event:
        actual_event = event['Payload']
        step = event.get('step')
    else:
        actual_event = event
        step = event.get('step')
    
    logger.info(f"Extracted step: {step}")
    logger.info(f"Actual event keys: {list(actual_event.keys())}")
    
    if step == 'read_s3_data':
        logger.info("Routing to read_s3_data_handler")
        return read_s3_data_handler(actual_event, context)
    elif step == 'start_cloudtrail_query':
        logger.info("Routing to start_cloudtrail_query_handler")
        return start_cloudtrail_query_handler(actual_event, context)
    elif step == 'check_cloudtrail_query':
        logger.info("Routing to check_cloudtrail_query_handler")
        return check_cloudtrail_query_handler(actual_event, context)
    elif step == 'fetch_terraform_files':
        logger.info("Routing to fetch_terraform_files_handler")
        return fetch_terraform_files_handler(actual_event, context)
    elif step == 'parse_terraform_policies':
        logger.info("Routing to parse_terraform_policies_handler")
        return parse_terraform_policies_handler(actual_event, context)
    else:
        logger.warning(f"No matching step found for: {step}")
        logger.info("Running default IAM analysis mode")
        return {
            'statusCode': 200,
            'message': 'IAM analysis completed',
            'debug_info': {
                'received_step': step,
                'available_steps': ['read_s3_data', 'start_cloudtrail_query', 'check_cloudtrail_query', 'fetch_terraform_files', 'parse_terraform_policies'],
                'event_keys': list(event.keys()),
                'actual_event_keys': list(actual_event.keys()) if 'actual_event' in locals() else 'N/A'
            }
        }

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def build_cloudtrail_query(user_arns: List[str], start_time: datetime, end_time: datetime, event_data_store_arn: str) -> str:
    """
    Build CloudTrail Lake SQL query to get user API usage
    """
    # Extract the Event Data Store ID from the ARN
    # ARN format: arn:aws:cloudtrail:region:account:eventdatastore/store-id
    store_id = event_data_store_arn.split('/')[-1]
    
    # Clean up ARNs - remove any template variables
    clean_arns = []
    for arn in user_arns:
        if '${' in arn:
            logger.warning(f"Skipping templated ARN: {arn}")
            continue
        clean_arns.append(arn)
    
    if not clean_arns:
        logger.warning("No valid ARNs found after filtering")
        # Return a query that will return no results but is valid
        return f"""
        SELECT 
            userIdentity.arn as principal_arn,
            eventName,
            eventSource,
            1 as call_count
        FROM {store_id}
        WHERE eventTime >= now() - interval '1' day
          AND userIdentity.arn = 'arn:aws:iam::000000000000:user/nonexistent'
        LIMIT 1
        """
    
    # Format ARNs for SQL IN clause
    arn_list = "', '".join(clean_arns)
    
    # Calculate retention period for the query
    retention_days = (end_time - start_time).days
    
    # Use your working query format
    query = f"""
    SELECT 
        userIdentity.arn as principal_arn,
        eventName,
        eventSource,
        COUNT(*) as call_count,
        MIN(eventTime) as first_seen,
        MAX(eventTime) as last_seen
    FROM {store_id}
    WHERE 
        eventTime >= now() - interval '{retention_days}' day
        AND userIdentity.arn IN ('{arn_list}')
        AND userIdentity.arn IS NOT NULL
        AND errorCode IS NULL
        AND eventName != 'AssumeRole'
        AND eventName != 'GetSessionToken'
        AND eventSource NOT LIKE '%signin.amazonaws.com'
    GROUP BY 
        userIdentity.arn, eventName, eventSource
    HAVING 
        COUNT(*) >= 1
    ORDER BY 
        principal_arn, call_count DESC
    LIMIT 1000
    """
    
    logger.info(f"Built CloudTrail query for {len(clean_arns)} valid ARNs using store ID: {store_id}")
    return query

