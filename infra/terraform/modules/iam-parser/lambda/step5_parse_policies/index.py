# step5_parse_policies/index.py - Parse Terraform policies and generate recommendations

import json
import re
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Parse Terraform policies and generate least privilege recommendations"""
    
    try:
        # Get input from previous steps
        terraform_files = event.get('terraform_files', {})
        user_api_usage = event.get('user_api_usage', {})
        users = event.get('users', [])
        
        logger.info(f"Parsing {len(terraform_files)} files for {len(users)} users")
        
        # Parse current policies from Terraform files
        user_policies = parse_terraform_policies(terraform_files, users)
        
        # Generate recommendations with specific file modifications
        policy_recommendations = generate_recommendations_with_file_changes(
            user_api_usage, user_policies, terraform_files
        )
        
        logger.info(f"Generated {len(policy_recommendations)} recommendations")
        
        return {
            'statusCode': 200,
            'user_policies': user_policies,
            'policy_recommendations': policy_recommendations,
            'file_modifications': extract_file_modifications(policy_recommendations),
            'recommendations_count': len(policy_recommendations),
            # Pass through from previous steps
            'terraform_files': terraform_files,
            'terraform_files_count': len(terraform_files),
            'user_api_usage': user_api_usage,
            'users': users,
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
            'user_policies': {},
            'policy_recommendations': {},
            'file_modifications': {},
            'recommendations_count': 0,
            # Preserve data flow
            'terraform_files': event.get('terraform_files', {}),
            'user_api_usage': event.get('user_api_usage', {}),
            'users': event.get('users', []),
            'metadata': event.get('metadata', {}),
            'iam_data': event.get('iam_data', {}),
            'roles': event.get('roles', []),
            'query_details': event.get('query_details', {})
        }

def parse_terraform_policies(tf_files, users):
    """Parse Terraform files to extract current IAM policies with locations"""
    user_policies = {}
    tf_name_to_user = {user['tf_resource_name']: user['name'] for user in users}
    
    for file_path, content in tf_files.items():
        # Find inline user policies with their exact locations
        inline_pattern = r'resource\s+"aws_iam_user_policy"\s+"([^"]+)"\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
        
        for match in re.finditer(inline_pattern, content, re.DOTALL):
            policy_name = match.group(1)
            policy_block = match.group(2)
            full_block = match.group(0)
            
            # Extract user reference
            user_match = re.search(r'user\s*=\s*aws_iam_user\.([^.\s]+)\.name', policy_block)
            if user_match:
                user_tf_name = user_match.group(1)
                
                if user_tf_name in tf_name_to_user:
                    user_name = tf_name_to_user[user_tf_name]
                    
                    if user_name not in user_policies:
                        user_policies[user_name] = {'inline_policies': [], 'attached_policies': []}
                    
                    # Extract policy document and actions
                    policy_doc, actions = extract_policy_document_and_actions(policy_block)
                    
                    user_policies[user_name]['inline_policies'].append({
                        'name': policy_name,
                        'file': file_path,
                        'policy_document': policy_doc,
                        'actions': actions,
                        'full_terraform_block': full_block,
                        'start_pos': match.start(),
                        'end_pos': match.end()
                    })
        
        # Find policy attachments
        attachment_pattern = r'resource\s+"aws_iam_user_policy_attachment"\s+"([^"]+)"\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
        
        for match in re.finditer(attachment_pattern, content, re.DOTALL):
            attachment_name = match.group(1)
            attachment_block = match.group(2)
            full_block = match.group(0)
            
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
                        'name': attachment_name,
                        'file': file_path,
                        'policy_arn': policy_arn,
                        'full_terraform_block': full_block,
                        'start_pos': match.start(),
                        'end_pos': match.end()
                    })
    
    return user_policies

def extract_policy_document_and_actions(policy_block):
    """Extract policy document and actions from Terraform block"""
    policy_match = re.search(r'policy\s*=\s*jsonencode\s*\(\s*(\{.*?\})\s*\)', policy_block, re.DOTALL)
    
    if policy_match:
        policy_text = policy_match.group(1)
        try:
            # Basic parsing - convert Terraform syntax to JSON
            policy_text = policy_text.replace('=', ':')
            policy_doc = json.loads(policy_text)
            
            # Extract actions
            actions = []
            statements = policy_doc.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            for statement in statements:
                stmt_actions = statement.get('Action', [])
                if isinstance(stmt_actions, str):
                    stmt_actions = [stmt_actions]
                actions.extend(stmt_actions)
            
            return policy_doc, actions
        except json.JSONDecodeError:
            logger.warning(f"Could not parse policy document")
            return {}, []
    
    return {}, []

def generate_recommendations_with_file_changes(user_api_usage, user_policies, terraform_files):
    """Generate recommendations with specific file modifications"""
    recommendations = {}
    
    for user_name in user_policies.keys():
        # Extract current permissions
        current_actions = set()
        policy_locations = []
        
        # From inline policies
        for policy in user_policies[user_name].get('inline_policies', []):
            actions = policy.get('actions', [])
            current_actions.update(actions)
            policy_locations.append(policy)
        
        # From attached policies (simplified - mark as wildcard for AWS managed policies)
        for policy in user_policies[user_name].get('attached_policies', []):
            if 'AdministratorAccess' in policy['policy_arn'] or 'PowerUserAccess' in policy['policy_arn']:
                current_actions.add('*')
                policy_locations.append(policy)
        
        # Get actual usage
        used_actions = set(user_api_usage.get(user_name, []))
        
        # Calculate differences
        unused_actions = current_actions - used_actions
        
        if unused_actions:
            # Generate specific file changes
            file_changes = generate_file_changes_for_user(
                user_name, unused_actions, used_actions, policy_locations, terraform_files
            )
            
            recommendations[user_name] = {
                'current_actions': list(current_actions),
                'used_actions': list(used_actions),
                'unused_actions': list(unused_actions),
                'recommendation': 'remove_unused',
                'risk_level': 'high' if '*' in current_actions else 'medium' if len(unused_actions) > 5 else 'low',
                'file_changes': file_changes
            }
    
    return recommendations

def generate_file_changes_for_user(user_name, unused_actions, used_actions, policy_locations, terraform_files):
    """Generate specific file changes for a user"""
    file_changes = {}
    
    for policy_location in policy_locations:
        file_path = policy_location['file']
        
        if file_path not in file_changes:
            file_changes[file_path] = {
                'original_content': terraform_files[file_path],
                'modified_content': terraform_files[file_path],
                'changes': []
            }
        
        # For inline policies, generate new policy with only used actions
        if 'actions' in policy_location:
            policy_actions = set(policy_location['actions'])
            actions_to_keep = policy_actions & used_actions
            
            if actions_to_keep and len(actions_to_keep) < len(policy_actions):
                # Create new policy document with only used actions
                new_policy_block = create_minimized_policy_block(
                    policy_location, actions_to_keep
                )
                
                # Replace the block in the file content
                original_content = file_changes[file_path]['modified_content']
                modified_content = (
                    original_content[:policy_location['start_pos']] +
                    new_policy_block +
                    original_content[policy_location['end_pos']:]
                )
                
                file_changes[file_path]['modified_content'] = modified_content
                file_changes[file_path]['changes'].append({
                    'type': 'policy_minimization',
                    'policy_name': policy_location['name'],
                    'removed_actions': list(policy_actions - actions_to_keep),
                    'kept_actions': list(actions_to_keep)
                })
            
            elif not actions_to_keep:
                # Remove the entire policy block if no actions are used
                original_content = file_changes[file_path]['modified_content']
                modified_content = (
                    original_content[:policy_location['start_pos']] +
                    original_content[policy_location['end_pos']:]
                )
                
                file_changes[file_path]['modified_content'] = modified_content
                file_changes[file_path]['changes'].append({
                    'type': 'policy_removal',
                    'policy_name': policy_location['name'],
                    'reason': 'No actions from this policy were used'
                })
    
    return file_changes

def create_minimized_policy_block(policy_location, actions_to_keep):
    """Create a new Terraform policy block with only the specified actions"""
    policy_name = policy_location['name']
    
    # Create simplified policy document
    new_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": sorted(list(actions_to_keep)),
                "Resource": "*"
            }
        ]
    }
    
    # Format as Terraform block
    return f'''resource "aws_iam_user_policy" "{policy_name}" {{
  name = "{policy_name}"
  user = aws_iam_user.{policy_location.get('user_ref', 'unknown')}.name

  policy = jsonencode({json.dumps(new_policy, indent=4)})
}}'''

def extract_file_modifications(recommendations):
    """Extract all file modifications from recommendations"""
    all_modifications = {}
    
    for user_name, rec in recommendations.items():
        if 'file_changes' in rec:
            for file_path, changes in rec['file_changes'].items():
                if file_path not in all_modifications:
                    all_modifications[file_path] = changes
                else:
                    # Merge changes if multiple users affect the same file
                    all_modifications[file_path]['modified_content'] = changes['modified_content']
                    all_modifications[file_path]['changes'].extend(changes['changes'])
    
    return all_modifications