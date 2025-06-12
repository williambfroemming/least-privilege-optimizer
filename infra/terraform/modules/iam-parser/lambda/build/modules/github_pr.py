from typing import Optional, Dict
import json
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
        auth = Auth.Token(github_token)
        self.github = Github(auth=auth)
        self.repo = self.github.get_repo(repo_name)
        
    def create_pull_request(
        self,
        title: str,
        body: str,
        base_branch: str = "main",
        head_branch: str = "iam-policy-updates",
        policy_changes: Optional[Dict] = None
    ):
        """Create a pull request with IAM policy changes
        
        Args:
            title: PR title
            body: PR description
            base_branch: Target branch (default: main)
            head_branch: Source branch (default: iam-policy-updates)
            policy_changes: Dictionary of policy changes to commit
        """
        try:
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
                logger.info(f"Found base branch {base_branch}")
            except Exception as e:
                logger.error(f"Base branch {base_branch} not found: {str(e)}")
                return {
                    "error": f"Base branch {base_branch} not found or not accessible",
                    "status": "failed"
                }
            
            # Try to get or create branch using a different approach
            try:
                # Try to get the branch first
                try:
                    head = self.repo.get_branch(head_branch)
                    # Branch exists, force update to match base
                    self.repo.get_git_ref(f"heads/{head_branch}").edit(sha=base_sha, force=True)
                    logger.info(f"Reset existing branch {head_branch} to {base_sha}")
                except Exception:
                    # Branch doesn't exist, create from base
                    ref = self.repo.create_git_ref(
                        ref=f"refs/heads/{head_branch}",
                        sha=base_sha
                    )
                    logger.info(f"Created new branch {head_branch}")
            except Exception as e:
                logger.error(f"Failed to handle branch: {str(e)}")
                return {
                    "error": f"Failed to handle branch: {str(e)}",
                    "status": "failed"
                }
            
            # Create/update policy files
            if policy_changes:
                for file_path, content in policy_changes.items():
                    try:
                        try:
                            # Try to get existing file
                            file = self.repo.get_contents(file_path, ref=head_branch)
                            # Update existing file
                            self.repo.update_file(
                                file_path,
                                f"Update IAM policy in {file_path}",
                                json.dumps(content, indent=2),
                                file.sha,
                                branch=head_branch
                            )
                        except Exception:
                            # File doesn't exist, create new file
                            self.repo.create_file(
                                file_path,
                                f"Add new IAM policy: {file_path}",
                                json.dumps(content, indent=2),
                                branch=head_branch
                            )
                        logger.info(f"Updated policy file: {file_path}")
                    except Exception as e:
                        logger.error(f"Failed to update file {file_path}: {str(e)}")
                        return {
                            "error": f"Failed to update file {file_path}: {str(e)}",
                            "status": "failed"
                        }
            
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
                    "status": "success"
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