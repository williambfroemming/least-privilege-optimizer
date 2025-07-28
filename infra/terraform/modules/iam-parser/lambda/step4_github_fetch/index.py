# step4_github_fetch/index.py - Fetch Terraform files from GitHub

import os
import json
import base64
import boto3
import urllib3
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Fetch Terraform files from GitHub repository"""
    
    try:
        # Get environment variables
        github_repo = os.environ['GITHUB_REPO']
        github_token_ssm_path = os.environ['GITHUB_TOKEN_SSM_PATH']
        
        # Get GitHub token from SSM
        ssm_client = boto3.client('ssm')
        response = ssm_client.get_parameter(
            Name=github_token_ssm_path,
            WithDecryption=True
        )
        github_token = response['Parameter']['Value']
        
        # Fetch Terraform files
        terraform_files = fetch_terraform_files(github_repo, github_token)
        
        logger.info(f"Fetched {len(terraform_files)} Terraform files")
        
        return {
            'statusCode': 200,
            'terraform_files': terraform_files,
            'terraform_files_count': len(terraform_files),
            'github_repo': github_repo,
            # Pass through from previous steps
            'user_api_usage': event.get('user_api_usage', {}),
            'users': event.get('users', []),
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
            'terraform_files': {},
            'terraform_files_count': 0,
            # Preserve data flow
            'user_api_usage': event.get('user_api_usage', {}),
            'users': event.get('users', []),
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {})
        }

def fetch_terraform_files(repo, token):
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
            return
        
        try:
            url = f"{base_url}/repos/{repo}/contents/{path}" if path else f"{base_url}/repos/{repo}/contents"
            response = http.request('GET', url, headers=headers)
            
            if response.status != 200:
                logger.warning(f"Failed to fetch {path}: {response.status}")
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
                    if 'content' in item:
                        content = base64.b64decode(item['content']).decode('utf-8')
                        terraform_files[item_path] = content
                        logger.info(f"Retrieved: {item_path}")
                    else:
                        # Fetch separately if needed
                        download_url = item.get('download_url')
                        if download_url:
                            file_response = http.request('GET', download_url)
                            if file_response.status == 200:
                                terraform_files[item_path] = file_response.data.decode('utf-8')
                                logger.info(f"Retrieved: {item_path}")
                
                elif item_type == 'dir':
                    skip_dirs = {'.git', '.github', '.terraform', 'node_modules', '__pycache__'}
                    if item_name not in skip_dirs:
                        scan_directory(item_path, max_depth, current_depth + 1)
                        
        except Exception as e:
            logger.error(f"Error scanning {path}: {e}")
    
    scan_directory()
    return terraform_files