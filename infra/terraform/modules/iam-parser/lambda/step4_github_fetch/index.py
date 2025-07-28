# step4_github_fetch/index.py - Fetch Terraform files from GitHub with improved parsing

import os
import json
import base64
import boto3
import urllib3
import logging
import re

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Fetch Terraform files from GitHub repository"""
    
    try:
        # Get environment variables
        github_repo = os.environ['GITHUB_REPO']
        github_token_ssm_path = os.environ['GITHUB_TOKEN_SSM_PATH']
        github_branch = os.environ.get('GITHUB_BRANCH', 'main')
        
        # Get GitHub token from SSM
        ssm_client = boto3.client('ssm')
        response = ssm_client.get_parameter(
            Name=github_token_ssm_path,
            WithDecryption=True
        )
        github_token = response['Parameter']['Value']
        
        # Fetch Terraform files
        terraform_files = fetch_terraform_files(github_repo, github_token, github_branch)
        
        logger.info(f"Fetched {len(terraform_files)} Terraform files from {github_repo}")
        
        # Extract user information from step 3 results
        users = event.get('users', [])
        user_api_usage = event.get('user_api_usage', {})
        
        # Map users to their policies for comparison
        user_policy_mapping = extract_user_policy_mapping(terraform_files, users)
        
        logger.info(f"Mapped {len(user_policy_mapping)} users to their policies")
        
        # Debug logging
        for user_name, policies in user_policy_mapping.items():
            inline_count = len(policies.get('inline_policies', []))
            attached_count = len(policies.get('attached_policies', []))
            logger.info(f"User {user_name}: {inline_count} inline, {attached_count} attached policies")
        
        return {
            'statusCode': 200,
            'terraform_files': terraform_files,
            'terraform_files_count': len(terraform_files),
            'github_repo': github_repo,
            'github_branch': github_branch,
            'user_policy_mapping': user_policy_mapping,
            # Pass through from previous steps
            'user_api_usage': user_api_usage,
            'users': users,
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {}),
            'batch_details': event.get('batch_details', []),
            'query_summary': event.get('query_summary', {})
        }
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return {
            'statusCode': 500,
            'error': str(e),
            'terraform_files': {},
            'terraform_files_count': 0,
            'user_policy_mapping': {},
            # Preserve data flow
            'user_api_usage': event.get('user_api_usage', {}),
            'users': event.get('users', []),
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {}),
            'batch_details': event.get('batch_details', []),
            'query_summary': event.get('query_summary', {})
        }

def fetch_terraform_files(repo, token, branch='main'):
    """Fetch .tf files from GitHub repository"""
    terraform_files = {}
    http = urllib3.PoolManager()
    base_url = "https://api.github.com"
    
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'IAM-Analyzer/1.0'
    }
    
    def scan_directory(path="", max_depth=5, current_depth=0):
        if current_depth > max_depth:
            logger.warning(f"Max depth reached at {path}")
            return
        
        try:
            url = f"{base_url}/repos/{repo}/contents/{path}?ref={branch}" if path else f"{base_url}/repos/{repo}/contents?ref={branch}"
            response = http.request('GET', url, headers=headers)
            
            if response.status == 404:
                logger.warning(f"Path not found: {path}")
                return
            elif response.status != 200:
                logger.warning(f"Failed to fetch {path}: HTTP {response.status}")
                return
            
            contents = json.loads(response.data.decode('utf-8'))
            if isinstance(contents, dict):
                contents = [contents]
            
            for item in contents:
                item_path = item.get('path', '')
                item_type = item.get('type', '')
                item_name = item.get('name', '')
                
                if item_type == 'file' and item_name.endswith('.tf'):
                    # Get file content
                    if 'content' in item and item['content']:
                        try:
                            content = base64.b64decode(item['content']).decode('utf-8')
                            terraform_files[item_path] = content
                            logger.info(f"Retrieved: {item_path} ({len(content)} chars)")
                        except Exception as decode_error:
                            logger.error(f"Failed to decode {item_path}: {decode_error}")
                    else:
                        # Fetch file content separately
                        download_url = item.get('download_url')
                        if download_url:
                            try:
                                file_response = http.request('GET', download_url)
                                if file_response.status == 200:
                                    content = file_response.data.decode('utf-8')
                                    terraform_files[item_path] = content
                                    logger.info(f"Retrieved via download: {item_path} ({len(content)} chars)")
                            except Exception as download_error:
                                logger.error(f"Failed to download {item_path}: {download_error}")
                
                elif item_type == 'dir':
                    # Skip common directories that won't contain relevant Terraform files
                    skip_dirs = {'.git', '.github', '.terraform', 'node_modules', '__pycache__', '.vscode', 'target', 'build'}
                    if item_name not in skip_dirs and not item_name.startswith('.'):
                        scan_directory(item_path, max_depth, current_depth + 1)
                        
        except json.JSONDecodeError as json_error:
            logger.error(f"JSON decode error for {path}: {json_error}")
        except Exception as e:
            logger.error(f"Error scanning {path}: {e}")
    
    logger.info(f"Starting scan of {repo} on branch {branch}")
    scan_directory()
    logger.info(f"Scan completed. Found {len(terraform_files)} .tf files")
    
    return terraform_files

def extract_user_policy_mapping(terraform_files, users):
    """Extract policy mappings for users from Terraform files with improved parsing"""
    user_policy_mapping = {}
    
    # Create mapping from terraform resource name to user name
    tf_name_to_user = {}
    for user in users:
        user_name = user.get('name', '')
        tf_resource_name = user.get('tf_resource_name', '')
        if user_name and tf_resource_name:
            tf_name_to_user[tf_resource_name] = user_name
    
    logger.info(f"Processing {len(tf_name_to_user)} users: {list(tf_name_to_user.values())}")
    
    # Process each Terraform file
    for file_path, content in terraform_files.items():
        logger.info(f"Scanning file: {file_path}")
        
        # Find all IAM user policy resources
        inline_policies = find_inline_policies(content, tf_name_to_user, file_path)
        attached_policies = find_attached_policies(content, tf_name_to_user, file_path)
        
        # Organize by user
        for policy_info in inline_policies:
            user_name = policy_info['user_name']
            if user_name not in user_policy_mapping:
                user_policy_mapping[user_name] = {
                    'inline_policies': [],
                    'attached_policies': [],
                    'managed_policies': []
                }
            user_policy_mapping[user_name]['inline_policies'].append(policy_info)
        
        for policy_info in attached_policies:
            user_name = policy_info['user_name']
            if user_name not in user_policy_mapping:
                user_policy_mapping[user_name] = {
                    'inline_policies': [],
                    'attached_policies': [],
                    'managed_policies': []
                }
            user_policy_mapping[user_name]['attached_policies'].append(policy_info)
    
    return user_policy_mapping

def find_inline_policies(content, tf_name_to_user, file_path):
    """Find inline IAM user policies in Terraform content"""
    policies = []
    
    # More flexible pattern for inline policies
    pattern = r'resource\s+"aws_iam_user_policy"\s+"([^"]+)"\s*\{'
    
    for match in re.finditer(pattern, content):
        policy_resource_name = match.group(1)
        start_pos = match.start()
        
        # Extract the complete resource block
        resource_block = extract_resource_block(content, start_pos)
        
        if not resource_block:
            continue
        
        # Find which user this policy belongs to
        user_ref_match = re.search(r'user\s*=\s*aws_iam_user\.([^.\s]+)\.name', resource_block)
        if not user_ref_match:
            continue
        
        tf_user_name = user_ref_match.group(1)
        user_name = tf_name_to_user.get(tf_user_name)
        
        if not user_name:
            logger.warning(f"Unknown user reference: {tf_user_name}")
            continue
        
        # Extract the policy JSON
        policy_json = extract_policy_json(resource_block)
        
        policies.append({
            'user_name': user_name,
            'policy_resource_name': policy_resource_name,
            'source_file': file_path,
            'policy_block': resource_block,
            'policy_json': policy_json
        })
        
        logger.info(f"Found inline policy: {policy_resource_name} for user {user_name}")
    
    return policies

def find_attached_policies(content, tf_name_to_user, file_path):
    """Find attached IAM user policies in Terraform content"""
    policies = []
    
    # Pattern for policy attachments
    pattern = r'resource\s+"aws_iam_user_policy_attachment"\s+"([^"]+)"\s*\{'
    
    for match in re.finditer(pattern, content):
        attachment_resource_name = match.group(1)
        start_pos = match.start()
        
        # Extract the complete resource block
        resource_block = extract_resource_block(content, start_pos)
        
        if not resource_block:
            continue
        
        # Find which user this attachment belongs to
        user_ref_match = re.search(r'user\s*=\s*aws_iam_user\.([^.\s]+)\.name', resource_block)
        if not user_ref_match:
            continue
        
        tf_user_name = user_ref_match.group(1)
        user_name = tf_name_to_user.get(tf_user_name)
        
        if not user_name:
            logger.warning(f"Unknown user reference: {tf_user_name}")
            continue
        
        # Extract the policy ARN
        arn_match = re.search(r'policy_arn\s*=\s*["\']([^"\']+)["\']', resource_block)
        if not arn_match:
            continue
        
        policy_arn = arn_match.group(1)
        
        policies.append({
            'user_name': user_name,
            'attachment_resource_name': attachment_resource_name,
            'source_file': file_path,
            'policy_arn': policy_arn,
            'attachment_block': resource_block
        })
        
        logger.info(f"Found attached policy: {policy_arn} for user {user_name}")
    
    return policies

def extract_resource_block(content, start_pos):
    """Extract a complete Terraform resource block using brace counting"""
    # Find the opening brace
    brace_pos = content.find('{', start_pos)
    if brace_pos == -1:
        return None
    
    brace_count = 0
    end_pos = brace_pos
    
    # Count braces to find the end of the block
    for i, char in enumerate(content[brace_pos:], brace_pos):
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                end_pos = i + 1
                break
    else:
        # No matching closing brace found
        return None
    
    return content[start_pos:end_pos]

def extract_policy_json(resource_block):
    """Extract the policy JSON from a Terraform resource block"""
    # Look for jsonencode() blocks
    jsonencode_match = re.search(r'policy\s*=\s*jsonencode\s*\(\s*(\{.*?\})\s*\)', resource_block, re.DOTALL)
    
    if jsonencode_match:
        policy_content = jsonencode_match.group(1)
        return policy_content
    
    # Fallback: look for direct JSON assignment
    json_match = re.search(r'policy\s*=\s*<<EOF\s*(.*?)\s*EOF', resource_block, re.DOTALL)
    if json_match:
        return json_match.group(1)
    
    # Another fallback: look for quoted JSON
    quoted_match = re.search(r'policy\s*=\s*["\']([^"\']+)["\']', resource_block)
    if quoted_match:
        return quoted_match.group(1)
    
    logger.warning("Could not extract policy JSON from resource block")
    return ""