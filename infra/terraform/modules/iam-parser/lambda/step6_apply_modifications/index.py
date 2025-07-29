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
        logger.info(f"DEBUG: Policy recommendations keys: {list(policy_recommendations.keys())}")
        logger.info(f"DEBUG: File modifications keys: {list(file_modifications.keys())}")
        
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

        logger.info(f"DEBUG: After filtering, have {len(filtered_modifications)} files with modifications")

        if not filtered_modifications:
            logger.info("No safe changes to apply after filtering")
            return create_response(False, "No safe changes to apply - all users have no API activity")

        # Apply actual modifications to file content
        processed_modifications = apply_all_terraform_modifications(
            filtered_modifications, policy_recommendations
        )

        logger.info(f"DEBUG: After processing, have {len(processed_modifications)} files with actual changes")

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
    
    logger.info(f"DEBUG: Starting filter_safe_modifications with {len(file_modifications)} files")
    logger.info(f"DEBUG: Policy recommendations: {list(policy_recommendations.keys())}")
    
    for file_path, file_data in file_modifications.items():
        logger.info(f"DEBUG: Processing file {file_path} with {len(file_data.get('changes', []))} changes")
        safe_changes = []
        
        for change in file_data.get('changes', []):
            policy_name = change.get('policy_name')
            logger.info(f"DEBUG: Processing change for policy {policy_name}")
            
            # Find the user recommendation that corresponds to this policy
            # by looking for a recommendation that references this policy name
            user_rec = None
            user_name = None
            
            for username, rec in policy_recommendations.items():
                logger.info(f"DEBUG: Checking user {username} for policy {policy_name}")
                policy_details = rec.get('policy_details', [])
                for policy_detail in policy_details:
                    if policy_detail.get('terraform_resource_name') == policy_name:
                        user_rec = rec
                        user_name = username
                        logger.info(f"DEBUG: Found user {user_name} for policy {policy_name}")
                        break
                if user_rec:
                    break
            
            if not user_rec:
                logger.warning(f"Could not find recommendation for policy {policy_name} - allowing change")
                safe_changes.append(change)
                continue
                
            used_actions = user_rec.get('used_actions', [])
            logger.info(f"DEBUG: User {user_name} has {len(used_actions)} used actions: {used_actions}")
            
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

    logger.info(f"DEBUG: Looking for policy block: '{policy_name}'")
    
    # Parse the content into blocks
    blocks = parse_terraform_blocks(content)
    logger.info(f"Found {len(blocks)} Terraform blocks")
    
    # Find the specific policy block we want to modify
    target_block = None
    for block in blocks:
        if (block['type'] == 'resource' and 
            block['resource_type'] == 'aws_iam_user_policy' and 
            block['name'] == policy_name):
            target_block = block
            break
    
    if not target_block:
        logger.warning(f"Policy block for {policy_name} NOT FOUND in content")
        return content
    
    logger.info(f"Found policy block for {policy_name}")
    
    # Modify the Action arrays in this block
    modified_block = modify_policy_actions(target_block, new_actions)
    
    # Rebuild the content with the modified block
    modified_content = rebuild_terraform_content(blocks, target_block, modified_block)
    
    logger.info(f"Successfully optimized policy {policy_name}")
    return modified_content

def parse_terraform_blocks(content):
    """Parse Terraform content into structured blocks"""
    blocks = []
    lines = content.split('\n')
    current_block = None
    brace_count = 0
    
    for line in lines:
        stripped = line.strip()
        
        # Start of a resource block
        if stripped.startswith('resource '):
            if current_block:
                blocks.append(current_block)
            
            # Parse resource declaration
            parts = stripped.split('"')
            if len(parts) >= 4:
                resource_type = parts[1]
                resource_name = parts[3]
                
                current_block = {
                    'type': 'resource',
                    'resource_type': resource_type,
                    'name': resource_name,
                    'lines': [line],
                    'start_line': len(blocks)
                }
                brace_count = 1
            else:
                current_block = {
                    'type': 'unknown',
                    'lines': [line],
                    'start_line': len(blocks)
                }
                brace_count = 1
        elif current_block:
            current_block['lines'].append(line)
            
            # Count braces
            for char in line:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        # End of block
                        blocks.append(current_block)
                        current_block = None
                        break
        else:
            # Lines outside of blocks
            if stripped:
                blocks.append({
                    'type': 'content',
                    'lines': [line],
                    'start_line': len(blocks)
                })
    
    # Add any remaining block
    if current_block:
        blocks.append(current_block)
    
    return blocks

def modify_policy_actions(block, new_actions):
    """Replace the entire policy content with a single optimized policy statement"""
    # Create a new optimized policy block
    policy_name = block['name']
    
    logger.info(f"Optimizing policy {policy_name} with actions: {new_actions}")
    
    # Extract the user name from the original block
    user_name = None
    original_policy_name = None
    
    for line in block['lines']:
        # Extract user name
        user_match = re.search(r'user\s*=\s*aws_iam_user\.([^.\s]+)\.name', line)
        if user_match:
            user_name = user_match.group(1)
        
        # Extract original policy name
        name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', line)
        if name_match:
            original_policy_name = name_match.group(1)
    
    if not user_name:
        logger.warning(f"Could not extract user name from policy {policy_name}")
        user_name = policy_name.replace('_policy', '')  # Fallback
    
    if not original_policy_name:
        logger.warning(f"Could not extract original policy name from policy {policy_name}")
        original_policy_name = policy_name  # Fallback
    
    logger.info(f"Extracted user name: {user_name}, original policy name: {original_policy_name} for policy {policy_name}")
    
    # Format the actions list
    formatted_actions = ',\n          '.join([f'"{action}"' for action in new_actions])
    
    # Create the new policy content with a single statement, preserving the original policy name
    new_policy_content = f'''resource "aws_iam_user_policy" "{policy_name}" {{
  name = "{original_policy_name}"
  user = aws_iam_user.{user_name}.name

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "LeastPrivilegeAccess"
        Effect = "Allow"
        Action = [
          {formatted_actions}
        ]
        Resource = "*"
      }}
    ]
  }})
}}'''
    
    logger.info(f"Created new policy content for {policy_name} with {len(new_actions)} actions")
    
    # Create modified block with the new content
    modified_block = block.copy()
    modified_block['lines'] = new_policy_content.split('\n')
    return modified_block

def rebuild_terraform_content(blocks, original_block, modified_block):
    """Rebuild the Terraform content with the modified block"""
    lines = []
    
    for block in blocks:
        if block == original_block:
            # Use the modified block instead
            lines.extend(modified_block['lines'])
        else:
            lines.extend(block['lines'])
    
    return '\n'.join(lines)

def apply_policy_removal_to_content(content, change):
    """Remove entire policy block from content"""
    policy_name = change['policy_name']
    
    # Pattern to match the entire policy resource block
    pattern = (
        rf'resource\s+"aws_iam_user_policy"\s+"{re.escape(policy_name)}"\s*\{{'
        r'[\s\S]*?'  # match everything inside the block
        r'\}}\s*'    # closing brace
    )
    
    # Debug: Check if the policy block exists at all
    policy_block_pattern = rf'resource\s+"aws_iam_user_policy"\s+"{re.escape(policy_name)}"'
    if re.search(policy_block_pattern, content):
        logger.info(f"Found policy block for {policy_name}")
    else:
        logger.warning(f"Policy block for {policy_name} NOT FOUND in content")
        # Show what policy blocks ARE in the content
        all_policies = re.findall(r'resource\s+"aws_iam_user_policy"\s+"([^"]+)"', content)
        logger.info(f"Available policy blocks in content: {all_policies}")
    
    # Remove the policy block
    modified_content, count = re.subn(pattern, '\n', content, flags=re.DOTALL)
    
    # Clean up multiple consecutive newlines
    modified_content = re.sub(r'\n{3,}', '\n\n', modified_content)
    
    if count == 0:
        logger.warning(f"Policy removal for {policy_name} didn't change content. Regex did not match.")
    else:
        logger.info(f"Successfully removed policy {policy_name} (removed {count} block(s))")
    
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