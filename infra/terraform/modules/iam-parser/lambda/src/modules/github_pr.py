from typing import Optional, Dict
import json
import os
import base64
from github import Github, Auth
from aws_lambda_powertools import Logger

logger = Logger(service="GitHubPRHandler")

class GitHubPRHandler:
    def __init__(self, github_token: str, repo_name: str):
        """Initialize GitHub client
        
        Args:
            github_token: GitHub personal access token
            repo_name: Repository name in format 'owner/repo'
        """
        if not github_token or not repo_name:
            raise ValueError("github_token and repo_name are required")
            
        auth = Auth.Token(github_token)
        self.github = Github(auth=auth)
        self.repo = self.github.get_repo(repo_name)
        
    def create_pull_request(
        self,
        title: str,
        body: str,
        base_branch: str = 'demo',  # Changed from 'main' to 'demo'
        head_branch: str = 'iam-policy-updates',
        policy_changes: Optional[Dict] = None
    ):
        """Create a pull request with IAM policy changes
        
        Args:
            title: PR title
            body: PR description
            base_branch: Target branch (defaults to "demo")
            head_branch: Source branch (defaults to "iam-policy-updates")
            policy_changes: Dictionary of policy changes to commit
        """
        try:
            logger.info(f"Creating PR: {title}")
            logger.info(f"Branch: {head_branch} -> {base_branch}")
            logger.info(f"Files to commit: {len(policy_changes) if policy_changes else 0}")
            
            # Verify repository access first
            try:
                self.repo.get_branches()
            except Exception as e:
                logger.error(f"Cannot access repository: {str(e)}")
                return {
                    "error": f"Repository access failed: {str(e)}",
                    "status": "failed"
                }

            # Get base branch and verify it exists
            try:
                base = self.repo.get_branch(base_branch)
                base_sha = base.commit.sha
                logger.info(f"Found base branch {base_branch} at {base_sha[:8]}")
            except Exception as e:
                logger.error(f"Base branch {base_branch} not found: {str(e)}")
                return {
                    "error": f"Base branch {base_branch} not found or not accessible",
                    "status": "failed"
                }
            
            # Handle branch creation/update
            try:
                # Try to get the branch first
                try:
                    head = self.repo.get_branch(head_branch)
                    # Branch exists, force update to match base
                    self.repo.get_git_ref(f"heads/{head_branch}").edit(sha=base_sha, force=True)
                    logger.info(f"Reset existing branch {head_branch} to {base_sha[:8]}")
                except Exception:
                    # Branch doesn't exist, create from base
                    ref = self.repo.create_git_ref(
                        ref=f"refs/heads/{head_branch}",
                        sha=base_sha
                    )
                    logger.info(f"Created new branch {head_branch} from {base_sha[:8]}")
            except Exception as e:
                logger.error(f"Failed to handle branch: {str(e)}")
                return {
                    "error": f"Failed to handle branch: {str(e)}",
                    "status": "failed"
                }
            
            # Ensure we have files to commit
            if not policy_changes:
                logger.warning("No policy changes provided - creating placeholder commit")
                # Create a simple README file to ensure there's at least one commit
                readme_content = f"""# IAM Policy Analysis Results

This branch was created by the IAM Analyzer Lambda function on {self._get_timestamp()}.

## Analysis Summary
- **Branch**: {head_branch}
- **Base**: {base_branch}
- **Files**: No policy changes detected in this run

This may indicate:
1. No Access Analyzer findings requiring action
2. All findings were filtered out (not in target resource list)
3. Issue with finding processing

Check the Lambda logs for more details.
"""
                policy_changes = {
                    "analysis-results/README.md": readme_content
                }
            
            # Track successful file commits
            files_committed = 0
            
            # Create/update policy files
            for file_path, content in policy_changes.items():
                try:
                    # Convert content to string format based on type
                    file_content = self._format_file_content(content, file_path)
                    
                    # Create commit message
                    commit_message = f"Update {file_path}"
                    if file_path.endswith('.tf'):
                        commit_message = f"Add/Update Terraform configuration: {file_path}"
                    elif file_path.endswith('.json'):
                        commit_message = f"Add/Update IAM policy: {file_path}"
                    elif file_path.endswith('.md'):
                        commit_message = f"Add/Update documentation: {file_path}"
                    
                    try:
                        # Try to get existing file
                        file = self.repo.get_contents(file_path, ref=head_branch)
                        # Only update if content is different
                        existing_content = base64.b64decode(file.content).decode('utf-8')
                        if existing_content.strip() != file_content.strip():
                            self.repo.update_file(
                                file_path,
                                commit_message,
                                file_content,
                                file.sha,
                                branch=head_branch
                            )
                            files_committed += 1
                            logger.info(f"Updated existing file: {file_path}")
                        else:
                            logger.info(f"File {file_path} unchanged, skipping")
                    except Exception:
                        # File doesn't exist, create new file
                        self.repo.create_file(
                            file_path,
                            commit_message,
                            file_content,
                            branch=head_branch
                        )
                        files_committed += 1
                        logger.info(f"Created new file: {file_path}")
                        
                except Exception as e:
                    logger.error(f"Failed to update file {file_path}: {str(e)}")
                    return {
                        "error": f"Failed to update file {file_path}: {str(e)}",
                        "status": "failed"
                    }
            
            logger.info(f"Successfully committed {files_committed} files to branch {head_branch}")
            
            # Verify there are commits on the branch before creating PR
            try:
                base_commit = self.repo.get_branch(base_branch).commit
                head_commit = self.repo.get_branch(head_branch).commit
                
                if base_commit.sha == head_commit.sha:
                    logger.error("No commits between base and head branch - this will cause PR creation to fail")
                    return {
                        "error": "No changes detected between branches - no commits to create PR from",
                        "status": "failed"
                    }
                else:
                    logger.info(f"Branch has {files_committed} new commits ready for PR")
            except Exception as e:
                logger.warning(f"Could not verify branch differences: {str(e)}")
            
            # Check for existing PR
            try:
                existing_prs = self.repo.get_pulls(
                    state='open',
                    head=f"{self.repo.owner.login}:{head_branch}",
                    base=base_branch
                )
                
                if existing_prs.totalCount > 0:
                    pr = existing_prs[0]
                    # Update existing PR
                    pr.edit(title=title, body=body)
                    logger.info(f"Updated existing PR #{pr.number}")
                    return {
                        "pr_number": pr.number,
                        "pr_url": pr.html_url,
                        "status": "success",
                        "files_committed": files_committed,
                        "action": "updated"
                    }
                else:
                    # Create new PR
                    pr = self.repo.create_pull(
                        title=title,
                        body=body,
                        base=base_branch,
                        head=head_branch
                    )
                    logger.info(f"Created new PR #{pr.number}")
                    return {
                        "pr_number": pr.number,
                        "pr_url": pr.html_url,
                        "status": "success",
                        "files_committed": files_committed,
                        "action": "created"
                    }
                    
            except Exception as e:
                logger.error(f"Failed to create/update PR: {str(e)}")
                return {
                    "error": f"Failed to create/update PR: {str(e)}",
                    "status": "failed"
                }
            
        except Exception as e:
            logger.error(f"Error creating pull request: {str(e)}")
            return {
                "error": str(e),
                "status": "failed"
            }
    
    def _format_file_content(self, content, file_path: str) -> str:
        """Format content appropriately based on file type and content type"""
        try:
            # If content is already a string, return as-is (for .tf files and markdown)
            if isinstance(content, str):
                return content
            
            # If content is a dict and file is JSON, format as JSON
            if isinstance(content, dict):
                if file_path.endswith('.json'):
                    return json.dumps(content, indent=2)
                else:
                    # For non-JSON files with dict content, convert to JSON string
                    return json.dumps(content, indent=2)
            
            # For other types, convert to string
            return str(content)
            
        except Exception as e:
            logger.error(f"Error formatting content for {file_path}: {str(e)}")
            return str(content)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for documentation"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")