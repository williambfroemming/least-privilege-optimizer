# step6_apply_modifications/index.py - Apply modifications to Terraform files

import json
import re
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Apply modifications to Terraform files based on recommendations"""
    
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
            logger.info("No recommendations found - skipping modifications")
            return create_response(False, "No recommendations to apply")

        if not file_modifications:
            logger.info("No file modifications found - skipping modifications")
            return create_response(False, "No file modifications found")

        # Filter out changes that would remove access when no API calls exist
        filtered_modifications = filter_safe_modifications(
            file_modifications, policy_recommendations
        )

        if not filtered_modifications:
            logger.info("No safe changes to apply after filtering")
            return create_response(False, "No safe changes to apply - all users have no API activity")

        # Apply actual modifications to file content
        processed_modifications = apply_all_terraform_modifications(
            filtered_modifications, policy_recommendations
        )

        if not processed_modifications:
            logger.info("No actual changes to apply after processing")
            return create_response(False, "No changes to apply after processing")

        # Generate summary
        summary = generate_modification_summary(processed_modifications, policy_recommendations)
        
        logger.info(f"Successfully processed {len(processed_modifications)} files with modifications")
        logger.info(f"Summary: {summary}")

        return {
            'statusCode': 200,
            'processed_modifications': processed_modifications,
            'summary': summary,
            'modifications_applied': True,
            # Pass through all data from previous steps
            'policy_recommendations': policy_recommendations,
            'file_modifications': file_modifications,
            'users': users,
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {}),
            'batch_details': event.get('batch_details', []),
            'query_summary': event.get('query_summary', {}),
            'terraform_files': event.get('terraform_files', {}),
            'user_policy_mapping': event.get('user_policy_mapping', {}),
            'user_api_usage': event.get('user_api_usage', {}),
            'github_repo': event.get('github_repo', ''),
            'github_branch': event.get('github_branch', '')
        }

    except Exception as e:
        logger.error(f"Error in step 6: {e}")
        return create_response(False, f"Error: {str(e)}")

def create_response(success, message):
    """Create standardized response"""
    return {
        'statusCode': 200,
        'modifications_applied': success,
        'message': message,
        'processed_modifications': {},
        'summary': {}
    }

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

def generate_modification_summary(processed_modifications, policy_recommendations):
    """Generate a summary of what modifications were applied"""
    files_modified = len(processed_modifications)
    policies_optimized = 0
    policies_removed = 0
    users_preserved = 0
    
    # Count changes by type
    for file_data in processed_modifications.values():
        for change in file_data.get('changes', []):
            if change['type'] == 'policy_optimization':
                policies_optimized += 1
            elif change['type'] == 'policy_removal':
                policies_removed += 1
    
    # Count users preserved (no API activity)
    for rec in policy_recommendations.values():
        if not rec.get('used_actions', []):
            users_preserved += 1
    
    return {
        'files_modified': files_modified,
        'policies_optimized': policies_optimized,
        'policies_removed': policies_removed,
        'users_preserved': users_preserved,
        'total_changes': policies_optimized + policies_removed
    } 