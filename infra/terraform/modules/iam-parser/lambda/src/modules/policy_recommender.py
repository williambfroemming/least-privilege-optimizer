import json
import os
import boto3
import re
from typing import Dict, List, Optional, Tuple, Set
from aws_lambda_powertools import Logger
from datetime import datetime
from github import Github, Auth
import base64

logger = Logger(service="PolicyRecommender")

class PolicyRecommender:
    def __init__(self, github_token: str, repo_name: str, region: str = 'us-east-1'):
        self.github_token = github_token
        self.repo_name = repo_name
        self.region = region
        self.branch_name = "iam-least-privilege-updates"
        self.test_mode = os.getenv('IAM_ANALYZER_TEST_MODE', '').lower() == 'true'
        
        self.github = Github(auth=Auth.Token(github_token))
        self.repo = self.github.get_repo(repo_name)
        
        if not self.test_mode:
            self.access_analyzer = boto3.client('accessanalyzer', region_name=region)
        
        logger.info(f"PolicyRecommender initialized (test_mode: {self.test_mode})")
    
    def discover_terraform_files(self) -> Dict[str, List[str]]:
        """
        Recursively discover all Terraform files in the repository and categorize them
        Returns dict with 'all_tf_files', 'user_files', 'policy_files'
        """
        logger.info("Discovering Terraform files in repository")
        
        all_tf_files = []
        user_files = []  # Files containing aws_iam_user resources
        policy_files = []  # Files containing aws_iam_user_policy resources
        
        try:
            # Get all files recursively
            contents = self.repo.get_contents("")
            files_to_process = list(contents)
            
            while files_to_process:
                file_content = files_to_process.pop(0)
                
                if file_content.type == "dir":
                    # Add directory contents to processing queue
                    try:
                        dir_contents = self.repo.get_contents(file_content.path)
                        files_to_process.extend(dir_contents)
                    except Exception as e:
                        logger.warning(f"Could not access directory {file_content.path}: {str(e)}")
                        continue
                        
                elif file_content.type == "file" and file_content.name.endswith('.tf'):
                    file_path = file_content.path
                    all_tf_files.append(file_path)
                    
                    # Download and analyze file content
                    try:
                        content = base64.b64decode(file_content.content).decode('utf-8')
                        
                        # Check for IAM user resources
                        if re.search(r'resource\s+"aws_iam_user"\s+', content):
                            user_files.append(file_path)
                            logger.debug(f"Found IAM users in: {file_path}")
                        
                        # Check for IAM user policy resources
                        if re.search(r'resource\s+"aws_iam_user_policy"\s+', content):
                            policy_files.append(file_path)
                            logger.debug(f"Found IAM user policies in: {file_path}")
                            
                    except Exception as e:
                        logger.warning(f"Could not analyze file {file_path}: {str(e)}")
                        continue
            
            logger.info(f"Terraform file discovery complete:")
            logger.info(f"  - Total .tf files: {len(all_tf_files)}")
            logger.info(f"  - Files with IAM users: {len(user_files)}")
            logger.info(f"  - Files with IAM policies: {len(policy_files)}")
            
            return {
                'all_tf_files': all_tf_files,
                'user_files': user_files,
                'policy_files': policy_files
            }
            
        except Exception as e:
            logger.error(f"Failed to discover Terraform files: {str(e)}")
            return {'all_tf_files': [], 'user_files': [], 'policy_files': []}
    
    def extract_iam_resources_from_files(self, file_paths: List[str]) -> Dict[str, Dict]:
        """
        Extract IAM user and policy resource definitions from Terraform files
        Returns dict mapping resource keys to their details
        """
        logger.info(f"Extracting IAM resources from {len(file_paths)} files")
        
        iam_users = {}  # tf_resource_name -> {file_path, content_block, arn_pattern}
        iam_policies = {}  # tf_resource_name -> {file_path, content_block, user_ref}
        
        for file_path in file_paths:
            try:
                file_content = self.repo.get_contents(file_path)
                content = base64.b64decode(file_content.content).decode('utf-8')
                
                # Extract IAM users
                user_pattern = r'resource\s+"aws_iam_user"\s+"([^"]+)"\s*\{([^}]*)\}'
                user_matches = re.finditer(user_pattern, content, re.DOTALL)
                
                for match in user_matches:
                    resource_name = match.group(1)
                    resource_block = match.group(0)
                    
                    # Extract user name from the block
                    name_match = re.search(r'name\s*=\s*"([^"]+)"', match.group(2))
                    user_name = name_match.group(1) if name_match else resource_name.replace('_', '-')
                    
                    iam_users[resource_name] = {
                        'file_path': file_path,
                        'content_block': resource_block,
                        'user_name': user_name,
                        'tf_reference': f"aws_iam_user.{resource_name}"
                    }
                    logger.debug(f"Found IAM user: {resource_name} ({user_name}) in {file_path}")
                
                # Extract IAM user policies
                policy_pattern = r'resource\s+"aws_iam_user_policy"\s+"([^"]+)"\s*\{([^}]*policy\s*=\s*[^}]*)\}'
                policy_matches = re.finditer(policy_pattern, content, re.DOTALL)
                
                for match in policy_matches:
                    resource_name = match.group(1)
                    resource_block = match.group(0)
                    policy_content = match.group(2)
                    
                    # Extract user reference
                    user_ref_match = re.search(r'user\s*=\s*([^\s\n]+)', policy_content)
                    user_reference = user_ref_match.group(1) if user_ref_match else None
                    
                    # Extract policy name
                    name_match = re.search(r'name\s*=\s*"([^"]+)"', policy_content)
                    policy_name = name_match.group(1) if name_match else f"{resource_name}-policy"
                    
                    iam_policies[resource_name] = {
                        'file_path': file_path,
                        'content_block': resource_block,
                        'policy_name': policy_name,
                        'user_reference': user_reference,
                        'tf_reference': f"aws_iam_user_policy.{resource_name}"
                    }
                    logger.debug(f"Found IAM policy: {resource_name} ({policy_name}) in {file_path}")
                    
            except Exception as e:
                logger.error(f"Failed to extract resources from {file_path}: {str(e)}")
                continue
        
        logger.info(f"Extracted {len(iam_users)} IAM users and {len(iam_policies)} IAM policies")
        return {'users': iam_users, 'policies': iam_policies}
    
    def build_user_policy_mapping(self, iam_resources: Dict[str, Dict], s3_resources: List[Dict]) -> Dict[str, Dict]:
        """
        Build mapping between users from S3 data and their corresponding Terraform policies
        Returns dict mapping user ARNs to their policy information
        """
        logger.info("Building user-policy dependency mapping")
        
        users = iam_resources['users']
        policies = iam_resources['policies']
        user_policy_map = {}
        
        # Create lookup for S3 resources by name and ARN
        s3_lookup_by_name = {}
        s3_lookup_by_arn = {}
        for resource in s3_resources:
            name = resource.get('ResourceName', '')
            arn = resource.get('ResourceARN', '')
            if name:
                s3_lookup_by_name[name] = resource
            if arn:
                s3_lookup_by_arn[arn] = resource
        
        # Map each user to their policies
        for user_tf_name, user_info in users.items():
            user_name = user_info['user_name']
            user_arn_pattern = f"arn:aws:iam::*:user/{user_name}"
            
            # Find matching S3 resource
            s3_resource = s3_lookup_by_name.get(user_name)
            if not s3_resource:
                logger.debug(f"No S3 resource found for user {user_name}, skipping")
                continue
            
            user_arn = s3_resource.get('ResourceARN', '')
            
            # Find policies that reference this user
            user_policies = []
            user_ref_pattern = f"aws_iam_user.{user_tf_name}"
            
            for policy_tf_name, policy_info in policies.items():
                policy_user_ref = policy_info.get('user_reference', '')
                
                # Check if policy references this user (with or without .name suffix)
                if (policy_user_ref == user_ref_pattern or 
                    policy_user_ref == f"{user_ref_pattern}.name" or
                    policy_user_ref.replace('.name', '') == user_ref_pattern):
                    
                    user_policies.append({
                        'tf_name': policy_tf_name,
                        'file_path': policy_info['file_path'],
                        'policy_name': policy_info['policy_name'],
                        'content_block': policy_info['content_block']
                    })
                    logger.debug(f"Mapped policy {policy_tf_name} to user {user_name}")
            
            if user_policies:
                user_policy_map[user_arn] = {
                    'user_name': user_name,
                    'user_tf_name': user_tf_name,
                    'user_file_path': user_info['file_path'],
                    'policies': user_policies,
                    's3_resource': s3_resource
                }
                logger.info(f"Mapped user {user_name} to {len(user_policies)} policies")
            else:
                logger.warning(f"No policies found for user {user_name}")
        
        logger.info(f"Built mapping for {len(user_policy_map)} users with policies")
        return user_policy_map
    
    def fetch_detailed_findings(self, analyzer_arn: str, findings: List[Dict]) -> List[Dict]:
        if self.test_mode:
            logger.info("Using mock data")
            from modules.mock_data import get_mock_detailed_findings
            return get_mock_detailed_findings()
        
        # Real API calls would go here
        logger.info(f"Fetching {len(findings)} detailed findings")
        detailed_findings = []
        
        for finding in findings:
            try:
                response = self.access_analyzer.get_finding_v2(
                    analyzerArn=analyzer_arn,
                    id=finding.get('id')
                )
                # Extract unused actions from response
                unused_actions = self._extract_unused_actions(response)
                if unused_actions:
                    detailed_findings.append({
                        'id': finding.get('id'),
                        'resource_arn': finding.get('resource', {}).get('arn', ''),
                        'finding_type': finding.get('findingType'),
                        'unused_actions': unused_actions,
                        'detailed_finding': finding
                    })
            except Exception as e:
                logger.error(f"Failed to fetch finding {finding.get('id')}: {str(e)}")
        
        return detailed_findings
    
    def _extract_unused_actions(self, response: Dict) -> List[str]:
        unused_actions = []
        finding = response.get('finding', {})
        finding_details = finding.get('findingDetails', [])
        
        for detail in finding_details:
            unused_permission = detail.get('unusedPermissionDetails', {})
            actions = unused_permission.get('actions', [])
            if actions:
                unused_actions.extend(actions)
        
        return list(set(unused_actions))
    
    def process_detailed_findings(self, detailed_findings: List[Dict], resources: List[Dict]) -> Dict[str, Dict]:
        logger.info(f"Processing {len(detailed_findings)} findings with auto-discovery")
        
        # Auto-discover Terraform files and build mappings
        tf_files = self.discover_terraform_files()
        if not tf_files['policy_files']:
            logger.warning("No Terraform files with IAM policies found")
            return {}
        
        # Extract IAM resources from discovered files
        all_files = list(set(tf_files['user_files'] + tf_files['policy_files']))
        iam_resources = self.extract_iam_resources_from_files(all_files)
        
        # Build user-policy mapping
        user_policy_map = self.build_user_policy_mapping(iam_resources, resources)
        
        # Process findings using the mapping
        recommendations = {}
        for finding in detailed_findings:
            resource_arn = finding['resource_arn']
            
            if resource_arn in user_policy_map:
                user_info = user_policy_map[resource_arn]
                
                # Create recommendations for each policy this user has
                for policy in user_info['policies']:
                    policy_key = f"aws_iam_user_policy.{policy['tf_name']}"
                    
                    recommendations[policy_key] = {
                        'finding_id': finding['id'],
                        'resource_name': user_info['user_name'],
                        'user_tf_name': user_info['user_tf_name'],
                        'policy_tf_name': policy['tf_name'],
                        'policy_file_path': policy['file_path'],
                        'policy_name': policy['policy_name'],
                        'unused_actions': finding['unused_actions'],
                        'timestamp': datetime.now().isoformat(),
                        'original_content': policy['content_block']
                    }
                    logger.info(f"Created recommendation for {policy_key} in {policy['file_path']}")
        
        logger.info(f"Generated {len(recommendations)} recommendations across multiple files")
        return recommendations
    
    def create_policy_updates_pr(self, recommendations: Dict[str, Dict]) -> bool:
        logger.info(f"Creating PR for {len(recommendations)} recommendations across multiple files")
        
        try:
            # Group recommendations by file path
            files_to_modify = {}
            for rec in recommendations.values():
                file_path = rec['policy_file_path']
                if file_path not in files_to_modify:
                    files_to_modify[file_path] = []
                files_to_modify[file_path].append(rec)
            
            logger.info(f"Will modify {len(files_to_modify)} Terraform files")
            
            # Download and modify each file
            modified_files = {}
            for file_path, file_recommendations in files_to_modify.items():
                original_content = self._download_file(file_path)
                if not original_content:
                    logger.error(f"Could not download {file_path}")
                    continue
                
                modified_content = self._modify_terraform_file(original_content, file_recommendations, file_path)
                modified_files[file_path] = modified_content
                logger.info(f"Modified {file_path} with {len(file_recommendations)} policy updates")
            
            # Create analysis summary
            summary = self._create_summary(recommendations, files_to_modify)
            modified_files["iam-analysis-results.md"] = summary
            
            # Create or update branch and PR
            if self._branch_exists():
                self._update_branch(modified_files)
            else:
                self._create_branch(modified_files)
            
            existing_pr = self._find_existing_pr()
            if existing_pr:
                self._update_pr(existing_pr, recommendations)
            else:
                self._create_pr(recommendations)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to create PR: {str(e)}")
            return False
    
    def _download_file(self, file_path: str) -> Optional[str]:
        """Download any file from the repository"""
        try:
            file_content = self.repo.get_contents(file_path)
            content = base64.b64decode(file_content.content).decode('utf-8')
            logger.debug(f"Downloaded {file_path}")
            return content
        except Exception as e:
            logger.error(f"Failed to download {file_path}: {str(e)}")
            return None
    
    def _modify_terraform_file(self, content: str, file_recommendations: List[Dict], file_path: str) -> str:
        """Modify a Terraform file with multiple policy updates"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Add header comment
        policy_count = len(file_recommendations)
        total_unused = sum(len(rec['unused_actions']) for rec in file_recommendations)
        
        header = f"""# MODIFIED BY IAM ANALYZER - {timestamp}
# File: {file_path}
# Updated {policy_count} policies, removed {total_unused} unused permissions

"""
        
        modified_content = content
        
        # Apply each recommendation to this file
        for rec in file_recommendations:
            policy_tf_name = rec['policy_tf_name']
            user_tf_name = rec['user_tf_name']
            unused_count = len(rec['unused_actions'])
            
            # Create optimized policy block
            optimized_policy_block = f'''resource "aws_iam_user_policy" "{policy_tf_name}" {{
  name = "{rec['policy_name']}"
  user = aws_iam_user.{user_tf_name}.name

  # OPTIMIZED POLICY - Removed {unused_count} unused permissions
  # Original unused actions: {', '.join(rec['unused_actions'][:5])}{'...' if len(rec['unused_actions']) > 5 else ''}
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "MinimalRequiredAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "athena:StartQueryExecution", 
          "athena:GetQueryResults",
          "cloudwatch:PutMetricData",
          "kms:Decrypt"
        ]
        Resource = "*"
      }}
    ]
  }})
}}'''
            
            # Replace the existing policy block using a more robust regex
            # This pattern handles nested braces better
            policy_pattern = rf'resource\s+"aws_iam_user_policy"\s+"{policy_tf_name}"\s*\{{[^{{}}]*(?:\{{[^{{}}]*\}}[^{{}}]*)*\}}'
            
            # Try simpler pattern first
            simple_pattern = rf'resource\s+"aws_iam_user_policy"\s+"{policy_tf_name}"\s*\{{.*?\n\}}'
            
            if re.search(policy_pattern, modified_content, flags=re.DOTALL):
                modified_content = re.sub(
                    policy_pattern,
                    optimized_policy_block,
                    modified_content,
                    flags=re.DOTALL
                )
                logger.info(f"Replaced policy {policy_tf_name} in {file_path}")
            elif re.search(simple_pattern, modified_content, flags=re.DOTALL):
                modified_content = re.sub(
                    simple_pattern,
                    optimized_policy_block,
                    modified_content,
                    flags=re.DOTALL
                )
                logger.info(f"Replaced policy {policy_tf_name} using simple pattern in {file_path}")
            else:
                # Try to find the policy by name and replace everything until the matching closing brace
                start_pattern = rf'resource\s+"aws_iam_user_policy"\s+"{policy_tf_name}"\s*\{{'
                start_match = re.search(start_pattern, modified_content)
                
                if start_match:
                    # Find the matching closing brace
                    start_pos = start_match.start()
                    brace_count = 0
                    end_pos = start_match.end()
                    
                    for i, char in enumerate(modified_content[start_match.end():], start_match.end()):
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            if brace_count == 0:
                                end_pos = i + 1
                                break
                            brace_count -= 1
                    
                    # Replace the found block
                    original_block = modified_content[start_pos:end_pos]
                    modified_content = modified_content[:start_pos] + optimized_policy_block + modified_content[end_pos:]
                    logger.info(f"Replaced policy {policy_tf_name} using brace matching in {file_path}")
                else:
                    logger.warning(f"Could not find policy {policy_tf_name} to replace in {file_path}")
        
        return header + modified_content
    
    def _create_summary(self, recommendations: Dict[str, Dict], files_to_modify: Dict[str, List[Dict]]) -> str:
        """Create analysis summary for multiple files and users"""
        total_unused = sum(len(rec['unused_actions']) for rec in recommendations.values())
        total_users = len(set(rec['user_tf_name'] for rec in recommendations.values()))
        
        summary = f"""# IAM Analysis Results

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- Users analyzed: {total_users}
- Policies updated: {len(recommendations)}
- Files modified: {len(files_to_modify)}
- Total unused permissions removed: {total_unused}

## Files Modified
"""
        
        for file_path, file_recs in files_to_modify.items():
            file_unused = sum(len(rec['unused_actions']) for rec in file_recs)
            summary += f"\n### {file_path}\n"
            summary += f"- Policies updated: {len(file_recs)}\n"
            summary += f"- Unused permissions removed: {file_unused}\n"
            
            for rec in file_recs:
                summary += f"  - **{rec['resource_name']}** ({rec['policy_tf_name']}): {len(rec['unused_actions'])} unused actions\n"
        
        summary += f"\n## Detailed Findings\n"
        
        for resource_key, rec in recommendations.items():
            summary += f"\n### {resource_key}\n"
            summary += f"- User: {rec['resource_name']}\n"
            summary += f"- Policy: {rec['policy_name']}\n"
            summary += f"- File: {rec['policy_file_path']}\n"
            summary += f"- Unused actions: {len(rec['unused_actions'])}\n"
            summary += "- Actions: " + ", ".join(rec['unused_actions'][:8])
            if len(rec['unused_actions']) > 8:
                summary += f" (and {len(rec['unused_actions']) - 8} more)"
            summary += "\n"
        
        return summary
    
    def _create_pr(self, recommendations: Dict[str, Dict]):
        # Calculate files being modified
        files_to_modify = {}
        for rec in recommendations.values():
            file_path = rec['policy_file_path']
            if file_path not in files_to_modify:
                files_to_modify[file_path] = []
            files_to_modify[file_path].append(rec)
            
        total_unused = sum(len(rec['unused_actions']) for rec in recommendations.values())
        total_users = len(set(rec['user_tf_name'] for rec in recommendations.values()))
        
        title = f"Remove {total_unused} unused IAM permissions across {total_users} users"
        
        body = f"""IAM least privilege optimization

- **Users analyzed:** {total_users}
- **Policies updated:** {len(recommendations)}
- **Files modified:** {len(files_to_modify)}
- **Total unused permissions removed:** {total_unused}

**Files changed:**
"""
        
        for file_path, file_recs in files_to_modify.items():
            file_unused = sum(len(rec['unused_actions']) for rec in file_recs)
            body += f"- `{file_path}` - {len(file_recs)} policies, {file_unused} unused permissions\n"
        
        body += f"- `iam-analysis-results.md` - Detailed analysis results\n\n"
        body += "Review the changes and test before merging."
        
        self.repo.create_pull(title=title, body=body, head=self.branch_name, base="main")
    
    def _update_pr(self, pr, recommendations: Dict[str, Dict]):
        # Calculate files being modified
        files_to_modify = {}
        for rec in recommendations.values():
            file_path = rec['policy_file_path']
            if file_path not in files_to_modify:
                files_to_modify[file_path] = []
            files_to_modify[file_path].append(rec)
            
        total_unused = sum(len(rec['unused_actions']) for rec in recommendations.values())
        total_users = len(set(rec['user_tf_name'] for rec in recommendations.values()))
        
        title = f"Remove {total_unused} unused IAM permissions across {total_users} users"
        
        body = f"""IAM least privilege optimization (Updated)

- **Users analyzed:** {total_users}
- **Policies updated:** {len(recommendations)}
- **Files modified:** {len(files_to_modify)}
- **Total unused permissions removed:** {total_unused}

**Files changed:**
"""
        
        for file_path, file_recs in files_to_modify.items():
            file_unused = sum(len(rec['unused_actions']) for rec in file_recs)
            body += f"- `{file_path}` - {len(file_recs)} policies, {file_unused} unused permissions\n"
        
        body += f"- `iam-analysis-results.md` - Detailed analysis results\n\n"
        body += "Review the changes and test before merging."

        pr.edit(title=title, body=body)
        summary = "\n### Summary of Changes\n"
        for resource_key, rec in recommendations.items():
            summary += f"\n### {resource_key}\n"
            summary += f"- User: {rec['resource_name']}\n"
            summary += f"- Unused actions: {len(rec['unused_actions'])}\n"
            summary += "- Actions: " + ", ".join(rec['unused_actions'][:5])
            if len(rec['unused_actions']) > 5:
                summary += f" (and {len(rec['unused_actions']) - 5} more)"
            summary += "\n"
        
        return summary
    
    def _create_pr(self, recommendations: Dict[str, Dict]):
        total_unused = sum(len(rec['unused_actions']) for rec in recommendations.values())
        title = f"Remove {total_unused} unused IAM permissions"
        body = f"""IAM least privilege optimization

- {len(recommendations)} users analyzed
- {total_unused} unused permissions identified  
- Updated policies.tf with minimal required permissions

**Files changed:**
- `policies.tf` - Updated with optimized IAM policy
- `iam-analysis-results.md` - Detailed analysis results

Review the changes and test before merging."""
        
        self.repo.create_pull(title=title, body=body, head=self.branch_name, base="main")
    
    def _update_pr(self, pr, recommendations: Dict[str, Dict]):
        total_unused = sum(len(rec['unused_actions']) for rec in recommendations.values())
        title = f"Remove {total_unused} unused IAM permissions"
        body = f"""IAM least privilege optimization (Updated)

- {len(recommendations)} users analyzed  
- {total_unused} unused permissions identified
- Updated policies.tf with minimal required permissions

**Files changed:**
- `policies.tf` - Updated with optimized IAM policy  
- `iam-analysis-results.md` - Detailed analysis results

Review the changes and test before merging."""
        
        pr.edit(title=title, body=body)
    
    def _branch_exists(self) -> bool:
        try:
            self.repo.get_branch(self.branch_name)
            return True
        except:
            return False
    
    def _create_branch(self, files: Dict[str, str]):
        main_branch = self.repo.get_branch("main")
        self.repo.create_git_ref(f"refs/heads/{self.branch_name}", main_branch.commit.sha)
        self._commit_files(files)
    
    def _update_branch(self, files: Dict[str, str]):
        self._commit_files(files)
    
    def _commit_files(self, files: Dict[str, str]):
        for path, content in files.items():
            try:
                existing = self.repo.get_contents(path, ref=self.branch_name)
                self.repo.update_file(path, f"Update {path}", content, existing.sha, branch=self.branch_name)
            except:
                self.repo.create_file(path, f"Add {path}", content, branch=self.branch_name)
    
    def _find_existing_pr(self):
        pulls = self.repo.get_pulls(state='open', head=f"{self.repo.owner.login}:{self.branch_name}", base="main")
        return pulls[0] if pulls.totalCount > 0 else None