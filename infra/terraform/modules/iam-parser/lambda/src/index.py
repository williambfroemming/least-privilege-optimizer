import os
import json
import boto3
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
from modules.iam_analyzer import Analyzer
from modules.github_pr import GitHubPRHandler
from modules.policy_recommender import PolicyRecommender

logger = Logger(service="iam-analyzer")

def get_github_token():
    """Fetch GitHub token from SSM Parameter Store"""
    try:
        ssm = boto3.client('ssm')
        response = ssm.get_parameter(
            Name='github-token',
            WithDecryption=True
        )
        return response['Parameter']['Value']
    except Exception as e:
        logger.error(f"Failed to retrieve GitHub token from SSM: {str(e)}")
        raise ValueError("Failed to retrieve GitHub token from SSM Parameter Store")

def validate_environment():
    """Validate required environment variables are set"""
    required_vars = ['GITHUB_REPO', 'ANALYZER_ARN', 'S3_BUCKET', 'S3_PREFIX']
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

@logger.inject_lambda_context
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    """
    Lambda handler that analyzes IAM policies and creates pull requests with updates
    
    """
    try:
        validate_environment()
        
        # Initialize clients with environment variables
        analyzer = Analyzer(region=os.environ.get('AWS_REGION'))
        github_handler = GitHubPRHandler(
            github_token=get_github_token(),
            repo_name=os.environ.get('GITHUB_REPO')
        )
        policy_recommender = PolicyRecommender(
            github_token=get_github_token(),
            repo_name=os.environ.get('GITHUB_REPO')
        )
        
        # Fetch resources and findings using S3 bucket and prefix from env
        resources = analyzer.fetch_resources_to_analyze(
            bucket_name=os.environ.get('S3_BUCKET'),
            prefix=os.environ.get('S3_PREFIX')
        )
        findings = analyzer.list_findings(
            os.environ.get('ANALYZER_ARN'),
            bucket_name=os.environ.get('S3_BUCKET'),
            prefix=os.environ.get('S3_PREFIX')
        )
        
        if not findings:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "No findings to analyze",
                    "status": "success"
                })
            }
            
        # Process findings and generate recommendations
        recommendations = policy_recommender.process_findings(findings, resources)
        
        if not recommendations:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "No policy updates required",
                    "status": "success"
                })
            }
            
        # Update Terraform configurations and create PR with defaults
        update_success = policy_recommender.update_terraform_policies(recommendations)
        if update_success:
            # Set reasonable defaults for PR variables
            pr_title = os.environ.get('PR_TITLE', 'Automated IAM Policy Updates - Least Privilege Optimization')
            pr_body = os.environ.get('PR_BODY', f'''
# IAM Policy Updates - Least Privilege Optimization

This PR contains automated updates to IAM policies based on Access Analyzer findings.

## Summary
- **Findings processed**: {len(findings)}
- **Policy recommendations**: {len(recommendations)}
- **Analysis date**: {json.dumps(context.aws_request_id if hasattr(context, 'aws_request_id') else 'N/A')}

## Changes
The following IAM policies have been updated to follow the principle of least privilege:

{chr(10).join([f"- {resource}" for resource in recommendations.keys()])}

## Review Notes
Please review the policy changes carefully before merging. These updates are based on actual usage patterns detected by AWS IAM Access Analyzer.

*This PR was generated automatically by the Least Privilege Optimizer.*
            '''.strip())
            base_branch = os.environ.get('BASE_BRANCH', 'main')
            head_branch = os.environ.get('HEAD_BRANCH', 'automated-iam-policy-updates')
            
            github_handler.create_pull_request(
                title=pr_title,
                body=pr_body,
                base_branch=base_branch,
                head_branch=head_branch
            )
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Successfully processed findings and generated recommendations",
                "status": "success" if update_success else "partial_success",
                "recommendations_count": len(recommendations),
                "findings_count": len(findings)
            })
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
