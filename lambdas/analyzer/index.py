import os
import json
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
from modules.iam_analyzer import AccessAnalyzerWrapper
from modules.github_pr import GitHubPRHandler

logger = Logger(service="iam-analyzer")

def validate_environment():
    """Validate required environment variables are set"""
    required_vars = ['GITHUB_TOKEN', 'GITHUB_REPO', 'AWS_REGION']
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

@logger.inject_lambda_context
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    """
    Lambda handler that analyzes IAM policies and creates pull requests with updates
    
    Expected event format:
    {
        "analyzer_arn": "arn:aws:access-analyzer:region:account:analyzer/name",
        "pr_title": "Update IAM policies based on analysis",
        "pr_body": "Automated PR for IAM policy updates",
        "base_branch": "main",  # optional
        "head_branch": "iam-updates"  # optional
    }
    """
    try:
        validate_environment()
        
        # Initialize clients
        analyzer = AccessAnalyzerWrapper(region=os.getenv('AWS_REGION'))
        github_handler = GitHubPRHandler(
            github_token=os.getenv('GITHUB_TOKEN'),
            repo_name=os.getenv('GITHUB_REPO')
        )
        
        # Get analyzer findings
        findings = analyzer.list_findings(event['analyzer_arn'])
        logger.info(f"Found {len(findings)} items to analyze")
        
        if not findings:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "No policy updates required",
                    "status": "success"
                })
            }
        
        # Generate policy recommendations
        policy_changes = {}
        for finding in findings:
            if finding.get('resourceType') == 'AWS::IAM::Policy':
                config = {
                    'existingPolicyDocument': finding.get('resource', {}).get('policy', {}),
                    'analyzedPolicyDocument': finding.get('analyzedPolicy', {})
                }
                generated_policy = analyzer.generate_policy('IAM', config)
                
                # Add to policy changes
                policy_path = f"policies/{finding['resourceId']}.json"
                policy_changes[policy_path] = generated_policy
        
        if not policy_changes:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "No policy updates required",
                    "status": "success"
                })
            }
        
        # Create pull request with changes
        pr_result = github_handler.create_pull_request(
            title=event.get('pr_title', 'Update IAM policies based on analysis'),
            body=event.get('pr_body', 'Automated PR with recommended IAM policy updates'),
            base_branch=event.get('base_branch', 'main'),
            head_branch=event.get('head_branch', 'iam-policy-updates'),
            policy_changes=policy_changes
        )
        
        return {
            "statusCode": 200,
            "body": json.dumps(pr_result)
        }
        
    except Exception as e:
        logger.exception("Lambda execution failed")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": str(e),
                "status": "failed"
            })
        }
