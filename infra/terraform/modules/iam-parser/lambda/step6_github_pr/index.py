# step6_github_pr/index.py - UPDATED VERSION - PRESERVE ACCESS WHEN NO API CALLS

import os
import json
import base64
import boto3
import urllib3
import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Create GitHub PR with actual Terraform file modifications"""
    
    try:
        # Get input from previous steps
        policy_recommendations = event.get('policy_recommendations', {})
        file_modifications = event.get('file_modifications', {})
        users = event.get('users', [])

        logger.info(f"Received {len(policy_recommendations)} recommendations")
        logger.info(f"Received {len(file_modifications)} file modifications")
        
        # Debug: Log what we received
        for file_path, file_data in file_modifications.items():
            changes_count = len(file_data.get('changes', []))
            logger.info(f"File {file_path}: {changes_count} changes")
            for i, change in enumerate(file_data.get('changes', [])):
                logger.info(f"  Change {i+1}: {change.get('type')} - {change.get('policy_name')}")

        if not policy_recommendations:
            logger.info("No recommendations found - skipping PR")
            return create_response(False, "No recommendations to apply")

        if not file_modifications:
            logger.info("No file modifications found - skipping PR")
            return create_response(False, "No file modifications found")

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

        # Apply actual modifications to file content BEFORE creating PR
        # Filter out changes that would remove access when no API calls exist
        filtered_modifications = filter_safe_modifications(
            file_modifications, policy_recommendations
        )

        if not filtered_modifications:
            logger.info("No safe changes to apply after filtering")
            return create_response(False, "No safe changes to apply - all users have no API activity")

        processed_modifications = apply_all_terraform_modifications(
            filtered_modifications, policy_recommendations
        )

        if not processed_modifications:
            logger.info("No actual changes to apply after processing")
            return create_response(False, "No changes to apply after processing")

        # Create PR with the processed modifications
        pr_result = create_github_pr_with_changes(
            github_repo, github_token, policy_recommendations, users, processed_modifications
        )

        logger.info(f"PR creation result: {pr_result['created']}")

        return create_response(
            pr_result['created'],
            pr_result.get('error', ''),
            pr_result
        )

    except Exception as e:
        logger.error(f"Error in step 6: {e}")
        return create_response(False, f"Error: {str(e)}")

def filter_safe_modifications(file_modifications, policy_recommendations):
    """Filter out modifications that would remove access when no API calls exist"""
    safe_modifications = {}
    
    for file_path, file_data in file_modifications.items():
        safe_changes = []
        
        for change in file_data.get('changes', []):
            policy_name = change.get('policy_name')
            
            # Find the user recommendation that corresponds to this policy
            # by looking for a recommendation that references this policy name
            user_rec = None
            user_name = None
            
            for username, rec in policy_recommendations.items():
                policy_details = rec.get('policy_details', [])
                for policy_detail in policy_details:
                    if policy_detail.get('terraform_resource_name') == policy_name:
                        user_rec = rec
                        user_name = username
                        break
                if user_rec:
                    break
            
            if not user_rec:
                logger.warning(f"Could not find recommendation for policy {policy_name} - allowing change")
                safe_changes.append(change)
                continue
                
            used_actions = user_rec.get('used_actions', [])
            
            if change['type'] == 'policy_removal':
                # Only allow removal if user has SOME used actions (meaning they had API activity)
                # If used_actions is empty, it means no API calls were found - preserve access
                if used_actions:
                    safe_changes.append(change)
                    logger.info(f"Allowing removal of {policy_name} - user {user_name} has {len(used_actions)} used actions")
                else:
                    logger.info(f"SKIPPING removal of {policy_name} - user {user_name} has no API activity, preserving access")
                    
            elif change['type'] == 'policy_optimization':
                # Only allow optimization if user has used actions
                # If no used actions, preserve the original broad permissions
                if used_actions:
                    safe_changes.append(change)
                    logger.info(f"Allowing optimization of {policy_name} - user {user_name} has {len(used_actions)} used actions")
                else:
                    logger.info(f"SKIPPING optimization of {policy_name} - user {user_name} has no API activity, preserving original permissions")
            else:
                # Allow other types of changes
                safe_changes.append(change)
        
        # Only include files that have safe changes
        if safe_changes:
            safe_modifications[file_path] = {
                **file_data,
                'changes': safe_changes
            }
            logger.info(f"File {file_path}: {len(safe_changes)} safe changes (was {len(file_data.get('changes', []))})")
        else:
            logger.info(f"File {file_path}: No safe changes - all users have no API activity")
    
    logger.info(f"Filtered to {len(safe_modifications)} files with safe modifications")
    return safe_modifications

def extract_username_from_policy_name(policy_name):
    """Extract username from policy name by matching against actual recommendation keys"""
    # Instead of guessing the username format, find the best match from actual recommendations
    return None  # We'll handle this differently in the calling function

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

def apply_all_terraform_modifications(file_modifications, policy_recommendations):
    """Apply all the planned changes to create actual modified content"""
    processed_modifications = {}
    
    for file_path, file_data in file_modifications.items():
        changes = file_data.get('changes', [])
        if not changes:
            logger.info(f"No changes for {file_path}")
            continue
            
        logger.info(f"Processing {len(changes)} changes for {file_path}")
        
        # Start with original content
        current_content = file_data['original_content']
        
        # Apply each change
        for change in changes:
            if change['type'] == 'policy_optimization':
                current_content = apply_policy_optimization_to_content(
                    current_content, change
                )
                logger.info(f"Applied optimization for {change['policy_name']}")
                
            elif change['type'] == 'policy_removal':
                current_content = apply_policy_removal_to_content(
                    current_content, change
                )
                logger.info(f"Applied removal for {change['policy_name']}")
        
        # Only include if content actually changed
        if current_content != file_data['original_content']:
            processed_modifications[file_path] = {
                'original_content': file_data['original_content'],
                'modified_content': current_content,
                'changes': changes
            }
            logger.info(f"File {file_path} has actual content changes")
        else:
            logger.warning(f"File {file_path} has no actual content changes after processing")
    
    logger.info(f"Processed {len(processed_modifications)} files with actual changes")
    return processed_modifications

def apply_policy_optimization_to_content(content, change):
    """Apply policy optimization by replacing the action list"""
    policy_name = change['policy_name']
    new_actions = change['new_actions']
    
    # Pattern to find the policy resource block
    pattern = rf'(resource\s+"aws_iam_user_policy"\s+"{re.escape(policy_name)}"\s*\{{[^}}]*?Action\s*=\s*\[)[^\]]*(\][^}}]*?\}})'
    
    # Create new action list
    formatted_actions = ',\n          '.join([f'"{action}"' for action in new_actions])
    new_action_block = f'\\1\n          {formatted_actions}\n        \\2'
    
    # Apply the replacement
    modified_content = re.sub(pattern, new_action_block, content, flags=re.DOTALL)
    
    if modified_content == content:
        logger.warning(f"Policy optimization for {policy_name} didn't change content")
    else:
        logger.info(f"Successfully optimized policy {policy_name}")
    
    return modified_content

def apply_policy_removal_to_content(content, change):
    """Remove entire policy block from content"""
    policy_name = change['policy_name']
    
    # Pattern to match the entire policy resource block
    pattern = rf'resource\s+"aws_iam_user_policy"\s+"{re.escape(policy_name)}"\s*\{{[^}}]*?\}}\s*\}}\s*\n*'
    
    # Remove the policy block
    modified_content = re.sub(pattern, '\n', content, flags=re.DOTALL)
    
    # Clean up multiple consecutive newlines
    modified_content = re.sub(r'\n{3,}', '\n\n', modified_content)
    
    if modified_content == content:
        logger.warning(f"Policy removal for {policy_name} didn't change content")
    else:
        logger.info(f"Successfully removed policy {policy_name}")
    
    return modified_content

def create_github_pr_with_changes(repo, token, recommendations, users, file_modifications):
    """Create GitHub PR with the actual file changes"""
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

        # Commit files with actual changes
        files_committed = []
        for file_path, file_data in file_modifications.items():
            # These should already have different content
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
        pr_description = generate_detailed_pr_description(recommendations, users, files_committed, file_modifications)

        pr_data = {
            "title": f"IAM Least Privilege: Optimize {len([r for r in recommendations.values() if r.get('recommendation') == 'optimize_permissions' and r.get('used_actions')])} users with API activity",
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

def generate_detailed_pr_description(recommendations, users, files_committed, file_modifications):
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
- **Users preserved (no API activity):** {len([r for r in recommendations.values() if not r.get('used_actions', [])])}
- **Unused permissions removed:** {total_unused}
- **Terraform files modified:** {len(files_committed)}

### 📁 File Changes
"""
    
    for file_path in files_committed:
        changes = file_modifications[file_path].get('changes', [])
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