def create_github_pr(repo, token, recommendations, users, file_modifications):
    """Create GitHub PR with actual Terraform file modifications"""
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
        
        main_data = json.loads(main_response.data.decode('utf-8'))
        main_sha = main_data['object']['sha']
        
        # Create new branch
        branch_data = {
            "ref": f"refs/heads/{branch_name}",
            "sha": main_sha
        }
        
        branch_response = http.request(
            'POST',
            f"{base_url}/repos/{repo}/git/refs",
            headers=headers,
            body=json.dumps(branch_data)
        )
        
        if branch_response.status != 201:
            raise Exception(f"Could not create branch: {branch_response.status}")
        
        # Commit modified Terraform files
        files_committed = []
        
        for file_path, file_data in file_modifications.items():
            if file_data['modified_content'] != file_data['original_content']:
                success = commit_file_changes(
                    http, headers, repo, branch_name, file_path, 
                    file_data['modified_content'], file_data['changes']
                )
                if success:
                    files_committed.append(file_path)
        
        # Also commit analysis summary
        summary_content = generate_detailed_analysis_summary(recommendations, users, file_modifications)
        commit_file_changes(
            http, headers, repo, branch_name, 
            'IAM_ANALYSIS_SUMMARY.md', summary_content, []
        )
        files_committed.append('IAM_ANALYSIS_SUMMARY.md')
        
        if not files_committed:
            logger.info("No files needed modification")
            return {
                'created': False,
                'error': 'No changes needed - all users are already following least privilege',
                'branch_name': branch_name
            }
        
        # Create pull request
        users_count = len([r for r in recommendations.values() if r['recommendation'] == 'remove_unused'])
        total_unused = sum(len(r['unused_actions']) for r in recommendations.values())
        
        pr_data = {
            "title": f"IAM Least Privilege: Remove {total_unused} unused permissions across {users_count} users",
            "body": generate_pr_description(recommendations, users, files_committed, file_modifications),
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
            return {
                'created': True,
                'pr_url': pr_result['html_url'],
                'pr_number': pr_result['number'],
                'branch_name': branch_name,
                'files_modified': files_committed
            }
        else:
            raise Exception(f"Could not create PR: {pr_response.status}")
            
    except Exception as e:
        logger.error(f"Failed to create PR: {e}")
        return {
            'created': False,
            'error': str(e),
            'branch_name': branch_name if 'branch_name' in locals() else 'unknown'
        }

def commit_file_changes(http, headers, repo, branch_name, file_path, content, changes):
    """Commit changes to a specific file"""
    try:
        # Check if file exists first
        existing_sha = get_file_sha(http, headers, repo, file_path)
        
        # Encode content to base64
        content_encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        
        url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
        
        commit_message = f"IAM Analyzer: Update {file_path}"
        if changes:
            change_summary = ", ".join([f"{c['type']} for {c.get('policy_name', 'policy')}" for c in changes])
            commit_message += f" - {change_summary}"
        
        data = {
            "message": commit_message,
            "content": content_encoded,
            "branch": branch_name
        }
        
        # If file exists, include its SHA for update
        if existing_sha:
            data["sha"] = existing_sha
        
        response = http.request(
            'PUT', 
            url, 
            headers=headers,
            body=json.dumps(data)
        )
        
        if response.status in [200, 201]:
            logger.info(f"Committed {file_path}")
            return True
        else:
            logger.error(f"Failed to commit {file_path}: {response.status}")
            return False
            
    except Exception as e:
        logger.error(f"Error committing {file_path}: {e}")
        return False

def get_file_sha(http, headers, repo, file_path):
    """Get the SHA of an existing file, or None if it doesn't exist"""
    try:
        url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
        response = http.request('GET', url, headers=headers)
        
        if response.status == 200:
            data = json.loads(response.data.decode('utf-8'))
            return data.get('sha', '')
        else:
            return ""
            
    except Exception:
        return ""

def generate_pr_description(recommendations, users, files_committed, file_modifications):
    """Generate detailed PR description"""
    users_count = len([r for r in recommendations.values() if r['recommendation'] == 'remove_unused'])
    total_unused = sum(len(r['unused_actions']) for r in recommendations.values())
    
    description = f"""## IAM Least Privilege Optimization

This PR implements least privilege IAM policies based on 30 days of CloudTrail analysis.

### Summary
- **Users optimized:** {users_count}
- **Unused permissions removed:** {total_unused}
- **Terraform files modified:** {len(files_committed)}

### File Changes

"""
    
    for file_path in files_committed:
        if file_path != 'IAM_ANALYSIS_SUMMARY.md' and file_path in file_modifications:
            changes = file_modifications[file_path].get('changes', [])
            description += f"#### `{file_path}`\n"
            
            for change in changes:
                if change['type'] == 'policy_minimization':
                    description += f"- **{change['policy_name']}**: Removed {len(change['removed_actions'])} unused actions, kept {len(change['kept_actions'])} used actions\n"
                elif change['type'] == 'policy_removal':
                    description += f"- **{change['policy_name']}**: Removed entire policy - {change['reason']}\n"
            description += "\n"
    
    description += """### User-by-User Analysis

"""
    
    for user_name, rec in recommendations.items():
        if rec['recommendation'] == 'remove_unused':
            risk = rec.get('risk_level', 'unknown').upper()
            description += f"**{user_name}** ({risk} RISK):\n"
            description += f"- Had {len(rec['current_actions'])} permissions, used {len(rec['used_actions'])}, removing {len(rec['unused_actions'])} unused\n"
            
            if len(rec['unused_actions']) <= 10:
                description += f"- Removed: `{', '.join(rec['unused_actions'])}`\n"
            else:
                description += f"- Removed: `{', '.join(rec['unused_actions'][:5])}` and {len(rec['unused_actions']) - 5} more\n"
            description += "\n"
    
    description += f"""
### Safety Notes
- Changes are based on **last 30 days** of API usage
- **Test thoroughly** in staging before merging to production
- **Monitor applications** after deployment
- See `IAM_ANALYSIS_SUMMARY.md` for complete analysis details

### Security Benefits
- Reduced attack surface by removing unused permissions
- Better compliance with least privilege principle
- Easier security auditing and policy management
- Limited blast radius if credentials are compromised

---
*Generated automatically by IAM Least Privilege Analyzer*
"""
    
    return description

def generate_detailed_analysis_summary(recommendations, users, file_modifications):
    """Generate comprehensive markdown analysis summary"""
    total_users = len(users)
    users_with_unused = len([r for r in recommendations.values() if r['recommendation'] == 'remove_unused'])
    total_unused = sum(len(r['unused_actions']) for r in recommendations.values())
    
    summary = f"""# IAM Least Privilege Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

## Executive Summary

This analysis reviewed {total_users} IAM users against 30 days of CloudTrail activity and identified {total_unused} unused permissions across {users_with_unused} users that can be optimized.

## Analysis Results

| Metric | Count |
|--------|-------|
| Total users analyzed | {total_users} |
| Users with unused permissions | {users_with_unused} |
| Total unused permissions found | {total_unused} |
| Terraform files modified | {len([f for f in file_modifications.keys() if f != 'IAM_ANALYSIS_SUMMARY.md'])} |

## File Modifications

"""
    
    for file_path, file_data in file_modifications.items():
        if file_path != 'IAM_ANALYSIS_SUMMARY.md':
            summary += f"""### {file_path}

**Changes made:**
"""
            for change in file_data.get('changes', []):
                if change['type'] == 'policy_minimization':
                    summary += f"- **{change['policy_name']}**: Minimized policy to include only {len(change['kept_actions'])} used actions (removed {len(change['removed_actions'])} unused)\n"
                elif change['type'] == 'policy_removal':
                    summary += f"- **{change['policy_name']}**: Removed entire policy - {change['reason']}\n"
            summary += "\n"
    
    summary += """## Detailed User Analysis

"""
    
    for user_name, rec in recommendations.items():
        if rec['recommendation'] == 'remove_unused':
            risk_level = rec.get('risk_level', 'unknown').upper()
            summary += f"""### {user_name}

- **Risk Level:** {risk_level}
- **Current Permissions:** {len(rec['current_actions'])} actions
- **Actually Used:** {len(rec['used_actions'])} actions
- **Unused (Removed):** {len(rec['unused_actions'])} actions

**Used Actions:**
```
{', '.join(sorted(rec['used_actions'])) if rec['used_actions'] else 'None'}
```

**Removed Actions:**
```
{', '.join(sorted(rec['unused_actions'])) if rec['unused_actions'] else 'None'}
```

"""
    
    summary += f"""
## Methodology

1. **Data Collection:** Analyzed CloudTrail logs for the past 30 days
2. **Policy Parsing:** Extracted current IAM permissions from Terraform files
3. **Usage Analysis:** Mapped actual API calls to IAM actions
4. **Optimization:** Generated minimal policies containing only used permissions
5. **File Generation:** Created modified Terraform files with optimized policies

## Implementation Notes

- All changes preserve the original Terraform structure
- Only removes permissions that were not used in the analysis period
- Maintains proper resource references and formatting
- Includes safety checks to prevent over-privileged access

## Next Steps

1. Review all changes in this PR carefully
2. Test in a staging environment with the modified policies
3. Monitor application functionality after deployment
4. Consider setting up regular analysis to maintain least privilege over time

---
*Analysis performed by IAM Least Privilege Analyzer*
"""
    
    return summary

def lambda_handler(event, context):
    """Generate GitHub PR with IAM policy recommendations"""
    
    try:
        # Get input from previous steps
        policy_recommendations = event.get('policy_recommendations', {})
        file_modifications = event.get('file_modifications', {})
        users = event.get('users', [])
        
        if not policy_recommendations:
            logger.info("No recommendations found - skipping PR")
            return {
                'statusCode': 200,
                'pr_created': False,
                'pr_message': 'No recommendations to apply',
                # Preserve all data
                'policy_recommendations': policy_recommendations,
                'file_modifications': file_modifications,
                'users': users,
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'user_api_usage': event.get('user_api_usage', {}),
                'terraform_files': event.get('terraform_files', {}),
                'query_details': event.get('query_details', {})
            }
        
        # Get environment variables
        github_repo = os.environ['GITHUB_REPO']
        github_token_ssm_path = os.environ['GITHUB_TOKEN_SSM_PATH']
        
        # Get GitHub token
        ssm_client = boto3.client('ssm')
        response = ssm_client.get_parameter(
            Name=github_token_ssm_path,
            WithDecryption=True
        )
        github_token = response['Parameter']['Value']
        
        # Create PR with actual file modifications
        pr_result = create_github_pr(
            github_repo, github_token, policy_recommendations, users, file_modifications
        )
        
        logger.info(f"PR creation result: {pr_result['created']}")
        
        return {
            'statusCode': 200,
            'pr_created': pr_result['created'],
            'pr_url': pr_result.get('pr_url', ''),
            'pr_number': pr_result.get('pr_number', ''),
            'branch_name': pr_result.get('branch_name', ''),
            'files_modified': pr_result.get('files_modified', []),
            'pr_error': pr_result.get('error', ''),
            # Pass through all data
            'policy_recommendations': policy_recommendations,
            'file_modifications': file_modifications,
            'users': users,
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'user_api_usage': event.get('user_api_usage', {}),
            'terraform_files': event.get('terraform_files', {}),
            'query_details': event.get('query_details', {})
        }
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return {
            'statusCode': 500,
            'error': str(e),
            'pr_created': False,
            # Preserve data flow
            'policy_recommendations': event.get('policy_recommendations', {}),
            'file_modifications': event.get('file_modifications', {}),
            'users': event.get('users', []),
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'user_api_usage': event.get('user_api_usage', {}),
            'terraform_files': event.get('terraform_files', {}),
            'query_details': event.get('query_details', {})
        }# step6_github_pr/index.py - Generate GitHub PR with actual Terraform file modifications

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
    """Generate GitHub PR with IAM policy recommendations"""
    
    try:
        # Get input from previous steps
        policy_recommendations = event.get('policy_recommendations', {})
        users = event.get('users', [])
        
        if not policy_recommendations:
            logger.info("No recommendations found - skipping PR")
            return {
                'statusCode': 200,
                'pr_created': False,
                'pr_message': 'No recommendations to apply',
                # Preserve all data
                'policy_recommendations': policy_recommendations,
                'users': users,
                'metadata': event.get('metadata', {}),
                'iam_data': event.get('iam_data', {}),
                'user_api_usage': event.get('user_api_usage', {}),
                'terraform_files': event.get('terraform_files', {}),
                'query_details': event.get('query_details', {})
            }
        
        # Get environment variables
        github_repo = os.environ['GITHUB_REPO']
        github_token_ssm_path = os.environ['GITHUB_TOKEN_SSM_PATH']
        
        # Get GitHub token
        ssm_client = boto3.client('ssm')
        response = ssm_client.get_parameter(
            Name=github_token_ssm_path,
            WithDecryption=True
        )
        github_token = response['Parameter']['Value']
        
        # Create PR
        pr_result = create_github_pr(github_repo, github_token, policy_recommendations, users)
        
        logger.info(f"PR creation result: {pr_result['created']}")
        
        return {
            'statusCode': 200,
            'pr_created': pr_result['created'],
            'pr_url': pr_result.get('pr_url', ''),
            'pr_number': pr_result.get('pr_number', ''),
            'branch_name': pr_result.get('branch_name', ''),
            'pr_error': pr_result.get('error', ''),
            # Pass through all data
            'policy_recommendations': policy_recommendations,
            'users': users,
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'user_api_usage': event.get('user_api_usage', {}),
            'terraform_files': event.get('terraform_files', {}),
            'query_details': event.get('query_details', {})
        }
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return {
            'statusCode': 500,
            'error': str(e),
            'pr_created': False,
            # Preserve data flow
            'policy_recommendations': event.get('policy_recommendations', {}),
            'users': event.get('users', []),
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'user_api_usage': event.get('user_api_usage', {}),
            'terraform_files': event.get('terraform_files', {}),
            'query_details': event.get('query_details', {})
        }

def create_github_pr(repo, token, recommendations, users):
    """Create GitHub PR with recommendations"""
    try:
        http = urllib3.PoolManager()
        base_url = "https://api.github.com"
        branch_name = f"iam-recommendations-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
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
        
        main_data = json.loads(main_response.data.decode('utf-8'))
        main_sha = main_data['object']['sha']
        
        # Create new branch
        branch_data = {
            "ref": f"refs/heads/{branch_name}",
            "sha": main_sha
        }
        
        branch_response = http.request(
            'POST',
            f"{base_url}/repos/{repo}/git/refs",
            headers=headers,
            body=json.dumps(branch_data)
        )
        
        if branch_response.status != 201:
            raise Exception(f"Could not create branch: {branch_response.status}")
        
        # Generate summary file content
        summary_content = generate_summary(recommendations, users)
        
        # Commit summary file
        content_encoded = base64.b64encode(summary_content.encode('utf-8')).decode('utf-8')
        
        file_data = {
            "message": "IAM Analysis Summary",
            "content": content_encoded,
            "branch": branch_name
        }
        
        file_response = http.request(
            'PUT',
            f"{base_url}/repos/{repo}/contents/IAM_ANALYSIS_SUMMARY.md",
            headers=headers,
            body=json.dumps(file_data)
        )
        
        if file_response.status not in [200, 201]:
            raise Exception(f"Could not commit file: {file_response.status}")
        
        # Create pull request
        users_count = len([r for r in recommendations.values() if r['recommendation'] == 'remove_unused'])
        total_unused = sum(len(r['unused_actions']) for r in recommendations.values())
        
        pr_data = {
            "title": f"IAM Least Privilege: Remove {total_unused} unused permissions across {users_count} users",
            "body": f"""## IAM Least Privilege Analysis

This PR contains recommendations to remove unused IAM permissions based on CloudTrail analysis.

### Summary
- Users analyzed: {len(users)}
- Users with unused permissions: {users_count}
- Total unused permissions: {total_unused}

### Files Modified
- IAM_ANALYSIS_SUMMARY.md - Detailed analysis results

### Important
- Review changes carefully before merging
- Test in staging environment first
- Monitor applications after applying changes

See IAM_ANALYSIS_SUMMARY.md for detailed recommendations.
""",
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
            return {
                'created': True,
                'pr_url': pr_result['html_url'],
                'pr_number': pr_result['number'],
                'branch_name': branch_name
            }
        else:
            raise Exception(f"Could not create PR: {pr_response.status}")
            
    except Exception as e:
        logger.error(f"Failed to create PR: {e}")
        return {
            'created': False,
            'error': str(e),
            'branch_name': branch_name if 'branch_name' in locals() else 'unknown'
        }

def generate_summary(recommendations, users):
    """Generate markdown summary of analysis"""
    total_users = len(users)
    users_with_unused = len([r for r in recommendations.values() if r['recommendation'] == 'remove_unused'])
    total_unused = sum(len(r['unused_actions']) for r in recommendations.values())
    
    summary = f"""# IAM Least Privilege Analysis Summary

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Analysis Results

- Total users analyzed: {total_users}
- Users with unused permissions: {users_with_unused}
- Total unused permissions found: {total_unused}

## Recommendations by User

"""
    
    for user_name, rec in recommendations.items():
        if rec['recommendation'] == 'remove_unused':
            summary += f"""### {user_name}
- Current permissions: {len(rec['current_actions'])} actions
- Actually used: {len(rec['used_actions'])} actions  
- Unused permissions: {len(rec['unused_actions'])} actions
- Risk level: {rec.get('risk_level', 'unknown').upper()}

**Unused permissions to remove:**
```
{', '.join(rec['unused_actions'][:10])}
{'... and ' + str(len(rec['unused_actions']) - 10) + ' more' if len(rec['unused_actions']) > 10 else ''}
```

"""
    
    summary += """
## Next Steps

1. Review the changes in this PR carefully
2. Test in a staging environment before applying to production
3. Monitor applications after applying changes
4. Set up regular analysis to maintain least privilege

## Security Benefits

- Reduced attack surface
- Better compliance with least privilege principle  
- Easier auditing
- Limited blast radius if credentials are compromised

---
Generated by IAM Least Privilege Analyzer
"""
    
    return summary