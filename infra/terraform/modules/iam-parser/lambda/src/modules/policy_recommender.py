import json
import os
import boto3
import re
from typing import Dict, List, Optional, Tuple, Set
from aws_lambda_powertools import Logger
from datetime import datetime
from github import Github, Auth, GithubException
import base64

logger = Logger(service="PolicyRecommender")

class PolicyRecommender:
    def __init__(self, github_token: str, repo_name: str, region: str = 'us-east-1'):
        self.github_token = github_token
        self.repo_name = repo_name
        self.region = region
        self.branch_name = self._generate_unique_branch_name()
        self.test_mode = os.getenv('IAM_ANALYZER_TEST_MODE', '').lower() == 'true'
        
        logger.info(f"Initializing GitHub client for repo: {repo_name}")
        self.github = Github(auth=Auth.Token(github_token))
        
        # Test connection
        user = self.github.get_user()
        logger.info(f"GitHub authenticated as: {user.login}")
        
        self.repo = self.github.get_repo(repo_name)
        logger.info(f"Connected to repository: {self.repo.full_name}")
        
        # Check permissions
        permissions = self.repo.permissions
        if not permissions.push:
            raise Exception("GitHub token does not have push permissions")
        
        if not self.test_mode:
            self.access_analyzer = boto3.client('accessanalyzer', region_name=region)
        
        logger.info(f"PolicyRecommender initialized (test_mode: {self.test_mode}, branch: {self.branch_name})")
    
    def _generate_unique_branch_name(self) -> str:
        """Generate a unique branch name using year and week number"""
        now = datetime.now()
        year = now.year
        iso_week = now.isocalendar()[1]
        branch_name = f"iam-optimization-{year}-w{iso_week:02d}"
        logger.info(f"Generated branch name: {branch_name}")
        return branch_name
    
    def fetch_detailed_findings(self, analyzer_arn: str, findings: List[Dict]) -> List[Dict]:
        if self.test_mode:
            logger.info("Using mock data")
            from modules.mock_data import get_mock_detailed_findings
            return get_mock_detailed_findings()
        
        logger.info(f"Fetching {len(findings)} detailed findings")
        detailed_findings = []
        
        for finding in findings:
            try:
                response = self.access_analyzer.get_finding_v2(
                    analyzerArn=analyzer_arn,
                    id=finding.get('id')
                )
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
        logger.info(f"Processing {len(detailed_findings)} findings")
        
        # Step 1: Extract user names from ARNs in findings
        users_with_findings = {}
        for finding in detailed_findings:
            resource_arn = finding['resource_arn']
            user_name = resource_arn.split('/')[-1]  # Extract user name from ARN
            users_with_findings[user_name] = finding
            logger.info(f"Found finding for user: {user_name} (ARN: {resource_arn})")
        
        # Step 2: Scan repository for Terraform files
        terraform_policies = self._scan_repository_for_policies()
        logger.info(f"Found {len(terraform_policies)} policies in repository")
        
        # Step 3: Match users with their Terraform policies
        recommendations = {}
        for user_name, finding in users_with_findings.items():
            matching_policies = self._find_policies_for_user(user_name, terraform_policies)
            
            for policy_info in matching_policies:
                policy_key = f"aws_iam_user_policy.{policy_info['tf_name']}"
                recommendations[policy_key] = {
                    'finding_id': finding['id'],
                    'resource_name': user_name,
                    'user_tf_name': policy_info['user_tf_name'],
                    'policy_tf_name': policy_info['tf_name'],
                    'policy_file_path': policy_info['file_path'],
                    'policy_name': policy_info['policy_name'],
                    'unused_actions': finding['unused_actions'],
                    'timestamp': datetime.now().isoformat(),
                    'original_content': policy_info['content']
                }
                logger.info(f"Matched user {user_name} to policy {policy_info['tf_name']} in {policy_info['file_path']}")
        
        logger.info(f"Generated {len(recommendations)} recommendations")
        return recommendations
    
    def _scan_repository_for_policies(self) -> List[Dict]:
        """Scan the entire repository for IAM user policies"""
        policies = []
        
        try:
            # Get all .tf files recursively
            tf_files = self._get_all_terraform_files()
            logger.info(f"Scanning {len(tf_files)} Terraform files")
            
            for file_path in tf_files:
                file_policies = self._extract_policies_from_file(file_path)
                policies.extend(file_policies)
                if file_policies:
                    logger.info(f"Found {len(file_policies)} policies in {file_path}")
            
            return policies
            
        except Exception as e:
            logger.error(f"Failed to scan repository: {str(e)}")
            return policies
    
    def _get_all_terraform_files(self) -> List[str]:
        """Get all .tf files in the repository"""
        tf_files = []
        
        try:
            contents = self.repo.get_contents("")
            files_to_process = list(contents)
            
            while files_to_process:
                file_content = files_to_process.pop(0)
                
                if file_content.type == "dir":
                    try:
                        dir_contents = self.repo.get_contents(file_content.path)
                        files_to_process.extend(dir_contents)
                    except Exception as e:
                        logger.warning(f"Could not access directory {file_content.path}: {str(e)}")
                        continue
                        
                elif file_content.type == "file" and file_content.name.endswith('.tf'):
                    tf_files.append(file_content.path)
            
            logger.info(f"Found {len(tf_files)} Terraform files")
            return tf_files
            
        except Exception as e:
            logger.error(f"Failed to get Terraform files: {str(e)}")
            return tf_files
    
    def _extract_policies_from_file(self, file_path: str) -> List[Dict]:
        """Extract all IAM user policies from a Terraform file"""
        policies = []
        
        try:
            content = self._download_file(file_path)
            if not content:
                return policies
            
            # Find all aws_iam_user_policy resources
            policy_pattern = r'resource\s+"aws_iam_user_policy"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
            matches = re.finditer(policy_pattern, content, re.DOTALL)
            
            for match in matches:
                tf_name = match.group(1)
                policy_block = match.group(0)
                policy_content = match.group(2)
                
                # Extract policy name
                name_match = re.search(r'name\s*=\s*"([^"]+)"', policy_content)
                policy_name = name_match.group(1) if name_match else tf_name
                
                # Extract user reference
                user_match = re.search(r'user\s*=\s*([^\s\n]+)', policy_content)
                user_ref = user_match.group(1) if user_match else ""
                
                # Extract user TF name from reference (e.g., aws_iam_user.alice_analyst_test.name -> alice_analyst_test)
                user_tf_name = ""
                if "aws_iam_user." in user_ref:
                    user_tf_match = re.search(r'aws_iam_user\.([^.]+)', user_ref)
                    user_tf_name = user_tf_match.group(1) if user_tf_match else ""
                
                policies.append({
                    'tf_name': tf_name,
                    'policy_name': policy_name,
                    'user_tf_name': user_tf_name,
                    'user_reference': user_ref,
                    'file_path': file_path,
                    'content': policy_block,
                    'start_pos': match.start(),
                    'end_pos': match.end()
                })
                
                logger.debug(f"Found policy {tf_name} for user {user_tf_name} in {file_path}")
            
            return policies
            
        except Exception as e:
            logger.error(f"Failed to extract policies from {file_path}: {str(e)}")
            return policies
    
    def _find_policies_for_user(self, user_name: str, terraform_policies: List[Dict]) -> List[Dict]:
        """Find Terraform policies that belong to a specific user"""
        matching_policies = []
        
        # Convert user name to Terraform naming convention
        user_tf_name = user_name.replace('-', '_')
        
        logger.info(f"Looking for policies for user: {user_name} (tf_name: {user_tf_name})")
        
        for policy in terraform_policies:
            # Check if this policy belongs to our user
            if policy['user_tf_name'] == user_tf_name:
                matching_policies.append(policy)
                logger.info(f"Found matching policy: {policy['tf_name']} in {policy['file_path']}")
            elif user_name.replace('-', '_') in policy['tf_name']:
                # Fallback: check if user name is part of policy name
                matching_policies.append(policy)
                logger.info(f"Found policy by name matching: {policy['tf_name']} in {policy['file_path']}")
        
        if not matching_policies:
            logger.warning(f"No policies found for user: {user_name}")
        
        return matching_policies
    
    def create_policy_updates_pr(self, recommendations: Dict[str, Dict]) -> bool:
        logger.info(f"Creating PR for {len(recommendations)} recommendations")
        
        if not recommendations:
            logger.warning("No recommendations provided")
            return True
        
        try:
            # Group recommendations by file
            files_to_modify = {}
            for rec in recommendations.values():
                file_path = rec['policy_file_path']
                if file_path not in files_to_modify:
                    files_to_modify[file_path] = []
                files_to_modify[file_path].append(rec)
            
            logger.info(f"Will modify {len(files_to_modify)} files")
            
            # Modify each file
            modified_files = {}
            for file_path, file_recommendations in files_to_modify.items():
                original_content = self._download_file(file_path)
                if original_content:
                    modified_content = self._modify_policies_in_file(original_content, file_recommendations)
                    modified_files[file_path] = modified_content
                    logger.info(f"Modified {file_path} with {len(file_recommendations)} policy updates")
            
            # Create summary
            summary = self._create_summary(recommendations)
            modified_files["iam-analysis-results.md"] = summary
            
            # Create debug info
            debug_info = self._create_debug_info(recommendations)
            modified_files["debug-matching-results.md"] = debug_info
            
            # Ensure branch exists
            if not self._ensure_branch_exists():
                logger.error("Failed to create branch")
                return False
            
            # Commit files
            if not self._commit_files(modified_files):
                logger.error("Failed to commit files")
                return False
            
            # Create PR
            if not self._create_or_update_pr(recommendations):
                logger.error("Failed to create PR")
                return False
            
            logger.info("Successfully created PR")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create PR: {str(e)}")
            return False
    
    def _modify_policies_in_file(self, content: str, file_recommendations: List[Dict]) -> str:
        """Modify specific policies in a file"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        total_unused = sum(len(rec['unused_actions']) for rec in file_recommendations)
        
        # Add header comment
        header = f"""# MODIFIED BY IAM ANALYZER - {timestamp}
# Updated {len(file_recommendations)} policies, removed {total_unused} unused permissions

"""
        
        modified_content = content
        replacements_made = 0
        
        # Sort recommendations by position (end to start) to avoid position shifts
        sorted_recs = sorted(file_recommendations, key=lambda x: x.get('start_pos', 0), reverse=True)
        
        for rec in sorted_recs:
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
            
            # Replace the specific policy
            new_content = self._replace_policy_in_content(modified_content, policy_tf_name, optimized_policy_block)
            if new_content != modified_content:
                modified_content = new_content
                replacements_made += 1
                logger.info(f"Successfully replaced policy {policy_tf_name}")
            else:
                logger.warning(f"Failed to replace policy {policy_tf_name}")
        
        logger.info(f"Made {replacements_made} policy replacements")
        
        if replacements_made > 0:
            return header + modified_content
        else:
            return modified_content
    
    def _replace_policy_in_content(self, content: str, policy_tf_name: str, new_block: str) -> str:
        """Replace a specific policy block in content"""
        
        # Find the exact policy block
        pattern = rf'resource\s+"aws_iam_user_policy"\s+"{re.escape(policy_tf_name)}"\s*\{{'
        match = re.search(pattern, content)
        
        if not match:
            logger.warning(f"Could not find policy {policy_tf_name}")
            return content
        
        # Find the matching closing brace
        start_pos = match.start()
        brace_count = 0
        pos = match.end() - 1  # Start from the opening brace
        
        for i, char in enumerate(content[pos:], pos):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i + 1
                    # Replace the block
                    result = content[:start_pos] + new_block + content[end_pos:]
                    logger.debug(f"Replaced policy {policy_tf_name}")
                    return result
        
        logger.warning(f"Could not find closing brace for policy {policy_tf_name}")
        return content
    
    def _create_debug_info(self, recommendations: Dict[str, Dict]) -> str:
        """Create debug information about the matching process"""
        debug_info = f"""# Debug: IAM Policy Matching Results

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- Total recommendations: {len(recommendations)}
- Files involved: {len(set(rec['policy_file_path'] for rec in recommendations.values()))}

## Detailed Matching Results
"""
        
        for rec in recommendations.values():
            debug_info += f"""
### {rec['resource_name']}
- **Finding ID**: {rec['finding_id']}
- **User TF Name**: {rec['user_tf_name']}
- **Policy TF Name**: {rec['policy_tf_name']}
- **File Path**: {rec['policy_file_path']}
- **Unused Actions**: {len(rec['unused_actions'])}
- **Actions**: {', '.join(rec['unused_actions'][:8])}{'...' if len(rec['unused_actions']) > 8 else ''}
"""
        
        return debug_info
    
    def _download_file(self, file_path: str) -> Optional[str]:
        """Download file from main branch"""
        try:
            file_content = self.repo.get_contents(file_path, ref="main")
            
            if file_content.encoding == 'base64':
                content = base64.b64decode(file_content.content).decode('utf-8')
            else:
                content = file_content.content
                if isinstance(content, bytes):
                    content = content.decode('utf-8')
            
            return content
        except Exception as e:
            logger.debug(f"Could not download {file_path}: {str(e)}")
            return None
    
    def _create_summary(self, recommendations: Dict[str, Dict]) -> str:
        """Create analysis summary"""
        total_unused = sum(len(rec['unused_actions']) for rec in recommendations.values())
        total_users = len(set(rec['user_tf_name'] for rec in recommendations.values()))
        
        summary = f"""# IAM Analysis Results

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- Users analyzed: {total_users}
- Policies updated: {len(recommendations)}
- Total unused permissions removed: {total_unused}

## Files Modified
"""
        
        files_modified = {}
        for rec in recommendations.values():
            file_path = rec['policy_file_path']
            if file_path not in files_modified:
                files_modified[file_path] = []
            files_modified[file_path].append(rec)
        
        for file_path, file_recs in files_modified.items():
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
            summary += f"- Actions: {', '.join(rec['unused_actions'][:8])}"
            if len(rec['unused_actions']) > 8:
                summary += f" (and {len(rec['unused_actions']) - 8} more)"
            summary += "\n"
        
        return summary
    
    def _ensure_branch_exists(self) -> bool:
        """Create unique branch"""
        try:
            branch_name = self.branch_name
            attempt = 1
            
            while True:
                try:
                    self.repo.get_branch(branch_name)
                    attempt += 1
                    hour_minute = datetime.now().strftime("%H%M")
                    branch_name = f"{self.branch_name}-{hour_minute}"
                    logger.info(f"Branch exists, trying: {branch_name}")
                except GithubException as e:
                    if e.status == 404:
                        main_branch = self.repo.get_branch("main")
                        self.repo.create_git_ref(
                            ref=f"refs/heads/{branch_name}", 
                            sha=main_branch.commit.sha
                        )
                        self.branch_name = branch_name
                        logger.info(f"Created new branch: {self.branch_name}")
                        return True
                    else:
                        logger.error(f"Error checking branch: {e.status}")
                        return False
                
                if attempt > 10:
                    logger.error("Too many attempts to create unique branch")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to create branch: {str(e)}")
            return False
    
    def _commit_files(self, files: Dict[str, str]) -> bool:
        """Commit files to branch"""
        try:
            for file_path, content in files.items():
                try:
                    existing_file = self.repo.get_contents(file_path, ref=self.branch_name)
                    self.repo.update_file(
                        path=file_path,
                        message=f"Update {file_path}",
                        content=content,
                        sha=existing_file.sha,
                        branch=self.branch_name
                    )
                    logger.info(f"Updated {file_path}")
                except GithubException as e:
                    if e.status == 404:
                        self.repo.create_file(
                            path=file_path,
                            message=f"Add {file_path}", 
                            content=content,
                            branch=self.branch_name
                        )
                        logger.info(f"Created {file_path}")
                    else:
                        raise
            return True
        except Exception as e:
            logger.error(f"Failed to commit files: {str(e)}")
            return False
    
    def _create_or_update_pr(self, recommendations: Dict[str, Dict]) -> bool:
        """Create new PR"""
        try:
            total_unused = sum(len(rec['unused_actions']) for rec in recommendations.values())
            total_users = len(set(rec['user_tf_name'] for rec in recommendations.values()))
            
            timestamp = datetime.now().strftime('%m/%d %H:%M')
            title = f"[{timestamp}] Remove {total_unused} unused IAM permissions across {total_users} users"
            
            files_modified = set(rec['policy_file_path'] for rec in recommendations.values())
            
            body = f"""IAM least privilege optimization - {self.branch_name}

- Users analyzed: {total_users}
- Policies updated: {len(recommendations)}
- Total unused permissions removed: {total_unused}
- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Files changed:
"""
            
            for file_path in sorted(files_modified):
                file_recs = [rec for rec in recommendations.values() if rec['policy_file_path'] == file_path]
                file_unused = sum(len(rec['unused_actions']) for rec in file_recs)
                body += f"- {file_path} - {len(file_recs)} policies, {file_unused} unused permissions\n"
            
            body += "- iam-analysis-results.md - Analysis results\n"
            body += "- debug-matching-results.md - Debug information\n\n"
            body += "Review and test before merging."
            
            pr = self.repo.create_pull(
                title=title, 
                body=body, 
                head=self.branch_name, 
                base="main"
            )
            
            logger.info(f"Created PR #{pr.number} on branch {self.branch_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create PR: {str(e)}")
            return False