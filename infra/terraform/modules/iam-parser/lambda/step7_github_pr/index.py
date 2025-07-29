# step7_github_pr/index.py - Create GitHub PR with processed modifications

import os
import json
import base64
import boto3
import urllib3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Create GitHub PR with processed Terraform file modifications"""
    
    try:
        # Get input from step 6
        processed_modifications = event.get('processed_modifications', {})
        policy_recommendations = event.get('policy_recommendations', {})
        users = event.get('users', [])
        summary = event.get('summary', {})

        logger.info(f"Received {len(processed_modifications)} processed modifications")
        logger.info(f"Summary: {summary}")
        
        # Debug: Log what we received
        for file_path, file_data in processed_modifications.items():
            changes_count = len(file_data.get('changes', []))
            logger.info(f"File {file_path}: {changes_count} changes")
            for i, change in enumerate(file_data.get('changes', [])):
                logger.info(f"  Change {i+1}: {change.get('type')} - {change.get('policy_name')}")

        if not processed_modifications:
            logger.info("No processed modifications found - skipping PR")
            return create_response(False, "No modifications to commit")

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

        # Create PR with the processed modifications
        pr_result = create_github_pr_with_changes(
            github_repo, github_token, policy_recommendations, users, processed_modifications, summary
        )

        logger.info(f"PR creation result: {pr_result['created']}")

        return create_response(
            pr_result['created'],
            pr_result.get('error', ''),
            pr_result
        )

    except Exception as e:
        logger.error(f"Error in step 7: {e}")
        return create_response(False, f"Error: {str(e)}")

def create_response(pr_created, pr_message, pr_result=None):
    """Create standardized response"""
    response = {
        'statusCode': 200,
        'pr_created': pr_created,
        'pr_message': pr_message
    }
    
    if pr_result:
        response.update({
            'pr_url': pr_result.get('pr_url', ''),
            'pr_number': pr_result.get('pr_number', ''),
            'branch_name': pr_result.get('branch_name', ''),
            'files_modified': pr_result.get('files_modified', [])
        })
    
    return response

def create_github_pr_with_changes(repo, token, recommendations, users, processed_modifications, summary):
    """Create GitHub PR with the processed file changes"""
    try:
        http = urllib3.PoolManager()
        base_url = "https://api.github.com"
        branch_name = f"iam-least-privilege-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
            'User-Agent': 'IAM-Analyzer/1.0'
        }

        # Get main branch SHA
        main_response = http.request('GET', f"{base_url}/repos/{repo}/git/refs/heads/main", headers=headers)
        if main_response.status != 200:
            main_response = http.request('GET', f"{base_url}/repos/{repo}/git/refs/heads/master", headers=headers)
        if main_response.status != 200:
            raise Exception("Could not find main/master branch")
        
        main_sha = json.loads(main_response.data.decode('utf-8'))['object']['sha']

        # Create new branch
        branch_data = {"ref": f"refs/heads/{branch_name}", "sha": main_sha}
        branch_response = http.request('POST', f"{base_url}/repos/{repo}/git/refs", headers=headers, body=json.dumps(branch_data))
        if branch_response.status != 201:
            raise Exception(f"Could not create branch: {branch_response.status}")

        logger.info(f"Created branch {branch_name}")

        # Commit files with processed modifications
        files_committed = []
        for file_path, file_data in processed_modifications.items():
            # These should already have different content from step 6
            success = commit_file_to_github(
                http, headers, repo, branch_name, file_path,
                file_data['modified_content'], file_data['changes']
            )
            if success:
                files_committed.append(file_path)
                logger.info(f"Successfully committed {file_path}")
            else:
                logger.error(f"Failed to commit {file_path}")

        if not files_committed:
            return {
                'created': False,
                'error': 'Failed to commit any files to GitHub',
                'branch_name': branch_name
            }

        # Create pull request
        pr_description = generate_detailed_pr_description(recommendations, users, files_committed, processed_modifications, summary)

        # Only count users who actually have API activity and are being optimized
        users_optimized = len([r for r in recommendations.values() 
                              if r.get('recommendation') == 'optimize_permissions' and r.get('used_actions')])

        pr_data = {
            "title": f"IAM Least Privilege: Optimize {users_optimized} users with API activity",
            "body": pr_description,
            "head": branch_name,
            "base": "main"
        }

        pr_response = http.request(
            'POST',
            f"{base_url}/repos/{repo}/pulls",
            headers=headers,
            body=json.dumps(pr_data)
        )

        if pr_response.status == 201:
            pr_result = json.loads(pr_response.data.decode('utf-8'))
            logger.info(f"Created PR #{pr_result['number']}: {pr_result['html_url']}")
            return {
                'created': True,
                'pr_url': pr_result['html_url'],
                'pr_number': pr_result['number'],
                'branch_name': branch_name,
                'files_modified': files_committed
            }
        else:
            error_msg = f"Failed to create PR: HTTP {pr_response.status}"
            logger.error(error_msg)
            return {
                'created': False,
                'error': error_msg,
                'branch_name': branch_name
            }

    except Exception as e:
        logger.error(f"Failed to create PR: {e}")
        return {
            'created': False,
            'error': str(e),
            'branch_name': branch_name if 'branch_name' in locals() else 'unknown'
        }

def commit_file_to_github(http, headers, repo, branch_name, file_path, content, changes):
    """Commit a single file to GitHub"""
    try:
        # Get existing file SHA if it exists
        existing_sha = get_existing_file_sha(http, headers, repo, file_path)
        
        # Encode content
        content_encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        
        # Prepare commit message
        commit_message = f"IAM Analyzer: Optimize {file_path}"
        if changes:
            change_summary = ", ".join([f"{c['type']}" for c in changes])
            commit_message += f" - {change_summary}"

        # Prepare commit data
        commit_data = {
            "message": commit_message,
            "content": content_encoded,
            "branch": branch_name
        }
        
        if existing_sha:
            commit_data["sha"] = existing_sha

        # Commit the file
        url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
        response = http.request('PUT', url, headers=headers, body=json.dumps(commit_data))
        
        success = response.status in [200, 201]
        if success:
            logger.info(f"Successfully committed {file_path}")
        else:
            logger.error(f"Failed to commit {file_path}: HTTP {response.status}")
            
        return success

    except Exception as e:
        logger.error(f"Error committing {file_path}: {e}")
        return False

def get_existing_file_sha(http, headers, repo, file_path):
    """Get the SHA of an existing file, or empty string if not found"""
    try:
        url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
        response = http.request('GET', url, headers=headers)
        if response.status == 200:
            file_info = json.loads(response.data.decode('utf-8'))
            return file_info.get('sha', '')
        return ''
    except Exception:
        return ''

def generate_detailed_pr_description(recommendations, users, files_committed, processed_modifications, summary):
    """Generate comprehensive PR description"""
    # Only count users who actually have API activity and are being optimized
    users_optimized = len([r for r in recommendations.values() 
                          if r.get('recommendation') == 'optimize_permissions' and r.get('used_actions')])
    total_unused = sum(len(r.get('unused_actions', [])) for r in recommendations.values() 
                      if r.get('used_actions'))  # Only count if user has API activity

    description = f"""## 🔒 IAM Least Privilege Optimization

This PR implements least privilege IAM policies based on 30 days of CloudTrail analysis.

⚠️ **IMPORTANT**: Users with no API activity in the last 30 days were left unchanged to preserve access.

### 📊 Summary
- **Users optimized:** {users_optimized}
- **Users preserved (no API activity):** {summary.get('users_preserved', 0)}
- **Unused permissions removed:** {total_unused}
- **Terraform files modified:** {len(files_committed)}
- **Policies optimized:** {summary.get('policies_optimized', 0)}
- **Policies removed:** {summary.get('policies_removed', 0)}

### 📁 File Changes
"""
    
    for file_path in files_committed:
        changes = processed_modifications[file_path].get('changes', [])
        description += f"#### `{file_path}`\n"
        for change in changes:
            if change['type'] == 'policy_optimization':
                description += f"- **{change['policy_name']}**: Replaced {len(change['removed_actions'])} broad permissions with {len(change['new_actions'])} specific actions\n"
            elif change['type'] == 'policy_removal':
                description += f"- **{change['policy_name']}**: Removed entire policy - {change['reason']}\n"
        description += "\n"

    description += "### 👥 User-by-User Analysis\n"
    
    # Users with changes
    for user_name, rec in recommendations.items():
        if rec.get('recommendation') == 'optimize_permissions' and rec.get('used_actions'):
            risk = rec.get('risk_level', 'unknown').upper()
            used_actions = rec.get('used_actions', [])
            unused_count = len(rec.get('unused_actions', []))
            
            description += f"**{user_name}** ({risk} RISK) - ✅ OPTIMIZED:\n"
            description += f"- Reduced to {len(used_actions)} used permissions, removed {unused_count} unused\n"
            description += f"- Now limited to: `{', '.join(used_actions[:5])}{'...' if len(used_actions) > 5 else ''}`\n\n"
    
    # Users preserved
    preserved_users = [user_name for user_name, rec in recommendations.items() 
                      if not rec.get('used_actions', [])]
    if preserved_users:
        description += "**Users Preserved (No API Activity):**\n"
        for user_name in preserved_users:
            description += f"- **{user_name}**: No API calls detected - keeping existing permissions\n"
        description += "\n"

    description += """### ⚠️ Safety Notes
- Changes are based on **last 30 days** of API usage
- **Users with no API activity were preserved** to avoid breaking access
- **Test thoroughly** in staging before merging to production
- **Monitor applications** after deployment
- Consider gradually rolling out changes to detect any missing permissions

### 🛡️ Security Benefits
- Reduced attack surface by removing unused permissions
- Better compliance with least privilege principle
- Easier security auditing and policy management
- Limited blast radius if credentials are compromised
- Conservative approach preserves access when usage is unclear

---
*Generated automatically by IAM Least Privilege Analyzer*
"""
    return description 