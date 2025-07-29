# step5_parse_policies/index.py - Generate recommendations using FetchTerraformFiles output

import json
import re
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Generate least privilege recommendations using already-parsed policy data"""
    
    try:
        # Get input from FetchTerraformFiles step
        user_policy_mapping = event.get('user_policy_mapping', {})
        user_api_usage = event.get('user_api_usage', {})
        users = event.get('users', [])
        terraform_files = event.get('terraform_files', {})
        
        logger.info(f"Processing {len(user_policy_mapping)} users with policy mappings")
        logger.info(f"Users with API usage: {list(user_api_usage.keys())}")
        
        # Generate recommendations using the pre-parsed policy data
        policy_recommendations = generate_recommendations_from_mapping(
            user_policy_mapping, user_api_usage, terraform_files
        )
        
        # Create file modifications structure for step 6
        file_modifications = create_file_modifications_for_step6(
            policy_recommendations, terraform_files
        )
        
        logger.info(f"Generated {len(policy_recommendations)} recommendations")
        logger.info(f"File modifications for {len(file_modifications)} files")
        
        return {
            'statusCode': 200,
            'policy_recommendations': policy_recommendations,
            'file_modifications': file_modifications,
            'recommendations_count': len(policy_recommendations),
            # Pass through all data from previous steps
            'user_policy_mapping': user_policy_mapping,
            'terraform_files': terraform_files,
            'terraform_files_count': len(terraform_files),
            'user_api_usage': user_api_usage,
            'users': users,
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {}),
            'batch_details': event.get('batch_details', []),
            'query_summary': event.get('query_summary', {}),
            'github_repo': event.get('github_repo', ''),
            'github_branch': event.get('github_branch', '')
        }
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return {
            'statusCode': 500,
            'error': str(e),
            'policy_recommendations': {},
            'file_modifications': {},
            'recommendations_count': 0,
            # Preserve data flow
            'user_policy_mapping': event.get('user_policy_mapping', {}),
            'terraform_files': event.get('terraform_files', {}),
            'user_api_usage': event.get('user_api_usage', {}),
            'users': event.get('users', []),
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {}),
            'batch_details': event.get('batch_details', []),
            'query_summary': event.get('query_summary', {}),
            'github_repo': event.get('github_repo', ''),
            'github_branch': event.get('github_branch', '')
        }

def generate_recommendations_from_mapping(user_policy_mapping, user_api_usage, terraform_files):
    """Generate recommendations using the pre-parsed policy mapping from FetchTerraformFiles"""
    recommendations = {}
    
    for user_name, policy_data in user_policy_mapping.items():
        logger.info(f"Processing user: {user_name}")
        
        # Extract current permissions from all policies
        current_actions = set()
        policy_details = []
        
        # From inline policies
        for policy in policy_data.get('inline_policies', []):
            # Extract actions from the policy JSON
            actions = extract_actions_from_policy_json(policy.get('policy_json', ''))
            current_actions.update(actions)
            
            # Use the policy resource name that was already extracted in step 4
            tf_resource_name = policy.get('policy_resource_name', 'unknown')
            
            policy_details.append({
                'type': 'inline',
                'terraform_resource_name': tf_resource_name,
                'source_file': policy['source_file'],
                'actions': actions,
                'policy_block': policy.get('policy_block', '')
            })
            
            logger.info(f"  Inline policy {tf_resource_name}: {len(actions)} actions")
        
        # From attached policies (AWS managed)
        for policy in policy_data.get('attached_policies', []):
            # Map managed policies to their effective actions
            actions = get_managed_policy_actions(policy['policy_arn'])
            current_actions.update(actions)
            
            # Use the attachment resource name that was already extracted in step 4
            tf_resource_name = policy.get('attachment_resource_name', 'unknown')
            
            policy_details.append({
                'type': 'attached',
                'terraform_resource_name': tf_resource_name,
                'source_file': policy['source_file'],
                'actions': actions,
                'policy_arn': policy['policy_arn'],
                'attachment_block': policy.get('attachment_block', '')
            })
            
            logger.info(f"  Attached policy {tf_resource_name}: {actions}")
        
        # Get actual API usage
        used_actions = set(user_api_usage.get(user_name, {}))
        
        logger.info(f"  Used actions: {used_actions}")
        logger.info(f"  Current actions: {len(current_actions)} total")
        
        # Find needed permissions (specific actions, implementing least privilege)
        needed_actions = find_needed_permissions(current_actions, used_actions)
        unused_actions = current_actions - needed_actions
        
        # Generate recommendation if there are optimizations to be made
        if unused_actions or not needed_actions:
            file_changes = create_change_plan(user_name, needed_actions, policy_details)
            
            recommendations[user_name] = {
                'current_actions': list(current_actions),
                'used_actions': list(used_actions),
                'needed_actions': list(needed_actions),
                'unused_actions': list(unused_actions),
                'recommendation': 'optimize_permissions',
                'risk_level': determine_risk_level(current_actions, unused_actions),
                'policy_details': policy_details,
                'file_changes': file_changes
            }
            
            logger.info(f"  Recommendation: Remove {len(unused_actions)} unused actions")
        else:
            logger.info(f"  No optimization needed for {user_name}")
    
    return recommendations

def extract_actions_from_policy_json(policy_json_text):
    """Extract actions from HCL/Terraform policy JSON text"""
    actions = set()
    
    if not policy_json_text:
        return list(actions)
    
    # Common action patterns in Terraform HCL
    action_patterns = [
        r'"([a-zA-Z0-9*:_-]+:[a-zA-Z0-9*_-]+)"',  # Standard actions like "s3:GetObject"
        r"'([a-zA-Z0-9*:_-]+:[a-zA-Z0-9*_-]+)'",  # Single quoted actions
        r'"([a-zA-Z0-9]+:\*)"',                   # Service wildcards like "s3:*"
        r'"(\*)"'                                  # Full wildcard "*"
    ]
    
    for pattern in action_patterns:
        matches = re.findall(pattern, policy_json_text)
        actions.update(matches)
    
    # Also look for unquoted patterns (common in HCL)
    unquoted_patterns = [
        r'([a-zA-Z0-9]+:\*)(?=\s*[,\]\}])',      # Service wildcards
        r'(\*)(?=\s*[,\]\}])'                     # Full wildcard
    ]
    
    for pattern in unquoted_patterns:
        matches = re.findall(pattern, policy_json_text)
        actions.update(matches)
    
    return list(actions)

def extract_resource_name_from_block(terraform_block):
    """Extract the Terraform resource name from a resource block"""
    if not terraform_block:
        return "unknown"
    
    # Match resource "type" "name" pattern
    match = re.search(r'resource\s+"[^"]+"\s+"([^"]+)"', terraform_block)
    if match:
        return match.group(1)
    
    return "unknown"

def get_managed_policy_actions(policy_arn):
    """Map AWS managed policies to their effective actions"""
    if 'AdministratorAccess' in policy_arn:
        return ['*']
    elif 'PowerUserAccess' in policy_arn:
        return ['*']  # Simplified
    elif 'ReadOnlyAccess' in policy_arn:
        return ['*:Get*', '*:List*', '*:Describe*']
    else:
        return ['unknown:managed:policy']

def find_needed_permissions(current_permissions, used_actions):
    """Find specific permissions needed (prefer specific actions over wildcards)"""
    needed = set()
    
    # Implement true least privilege: only grant what was actually used
    for used_action in used_actions:
        needed.add(used_action)
    
    return needed

def determine_risk_level(current_actions, unused_actions):
    """Determine risk level based on permissions"""
    if '*' in current_actions:
        return 'high'
    elif len(unused_actions) > 10:
        return 'high'
    elif len(unused_actions) > 5:
        return 'medium'
    else:
        return 'low'

def create_change_plan(user_name, needed_actions, policy_details):
    """Create a plan for what changes need to be made"""
    changes_by_file = {}
    
    for policy in policy_details:
        source_file = policy['source_file']
        
        # Convert relative path to match terraform_files structure
        if not source_file.startswith('infra/'):
            source_file = f"infra/sample-iac-app/terraform/{source_file}"
        
        if source_file not in changes_by_file:
            changes_by_file[source_file] = {
                'changes': []
            }
        
        if policy['type'] == 'inline':
            if needed_actions:
                # Optimize this policy to only include needed actions
                removed_actions = [a for a in policy['actions'] if a not in needed_actions]
                
                if removed_actions:  # Only add change if there are actions to remove
                    changes_by_file[source_file]['changes'].append({
                        'type': 'policy_optimization',
                        'policy_name': policy['terraform_resource_name'],
                        'removed_actions': removed_actions,
                        'new_actions': list(needed_actions),
                        'optimization_type': 'replace_with_specific_actions'
                    })
            else:
                # Remove this policy entirely if no actions are needed
                changes_by_file[source_file]['changes'].append({
                    'type': 'policy_removal',
                    'policy_name': policy['terraform_resource_name'],
                    'reason': 'No actions from this policy were used'
                })
        
        elif policy['type'] == 'attached':
            # For now, we'll note attached policies but not modify them
            # In a real implementation, you might want to replace with inline policies
            logger.info(f"User {user_name} has attached policy {policy['policy_arn']} - leaving unchanged")
    
    return changes_by_file

def create_file_modifications_for_step6(recommendations, terraform_files):
    """Create the file_modifications structure that step 6 expects"""
    file_modifications = {}
    
    logger.info(f"DEBUG: Processing {len(recommendations)} recommendations")
    
    # Collect all changes by file
    for user_name, rec in recommendations.items():
        logger.info(f"DEBUG: Processing user {user_name}")
        logger.info(f"DEBUG: User rec keys: {list(rec.keys())}")
        
        if 'file_changes' in rec:
            logger.info(f"DEBUG: User {user_name} has file_changes: {list(rec['file_changes'].keys())}")
            
            for file_path, changes in rec['file_changes'].items():
                logger.info(f"DEBUG: Processing file {file_path}")
                logger.info(f"DEBUG: Changes structure: {list(changes.keys())}")
                logger.info(f"DEBUG: Changes content: {changes}")
                
                if file_path not in file_modifications:
                    file_modifications[file_path] = {
                        'original_content': terraform_files.get(file_path, ''),
                        'modified_content': terraform_files.get(file_path, ''),  # Step 6 will apply changes
                        'changes': []
                    }
                
                # Add all changes for this file
                if 'changes' in changes:
                    logger.info(f"DEBUG: Adding {len(changes['changes'])} changes from {user_name} to {file_path}")
                    file_modifications[file_path]['changes'].extend(changes['changes'])
                else:
                    logger.warning(f"DEBUG: No 'changes' key found in changes structure for {user_name}, {file_path}")
        else:
            logger.info(f"DEBUG: User {user_name} has no file_changes")
    
    # Remove duplicates from changes
    for file_path in file_modifications:
        seen_changes = set()
        unique_changes = []
        
        for change in file_modifications[file_path]['changes']:
            # Create a unique key for each change
            change_key = (change['type'], change['policy_name'])
            
            if change_key not in seen_changes:
                seen_changes.add(change_key)
                unique_changes.append(change)
        
        file_modifications[file_path]['changes'] = unique_changes
    
    logger.info(f"Created file modifications for {len(file_modifications)} files")
    for file_path, mods in file_modifications.items():
        logger.info(f"  {file_path}: {len(mods['changes'])} changes")
        for change in mods['changes']:
            logger.info(f"    - {change['type']}: {change['policy_name']}")
    
    return file_modifications