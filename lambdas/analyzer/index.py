import os
import json
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
from modules.iam_analyzer import Analyzer
from modules.github_pr import GitHubPRHandler
from modules.policy_recommender import PolicyRecommender

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
        "bucket_name": "my-bucket-name",  # required for fetching resources
        "pr_title": "Update IAM policies based on analysis",
        "pr_body": "Automated PR for IAM policy updates",
        "base_branch": "main",  # optional
        "head_branch": "iam-updates"  # optional
    }
    """
    try:
        validate_environment()
        
        if 'bucket_name' not in event:
            raise ValueError("bucket_name is required in the event payload")
            
        # Initialize clients
        analyzer = Analyzer(region=os.getenv('AWS_REGION'))
        github_handler = GitHubPRHandler(
            github_token=os.getenv('GITHUB_TOKEN'),
            repo_name=os.getenv('GITHUB_REPO')
        )
        policy_recommender = PolicyRecommender(
            github_token=os.getenv('GITHUB_TOKEN'),
            repo_name=os.getenv('GITHUB_REPO')
        )
        
        # Fetch resources and findings
        resources = analyzer.fetch_resources_to_analyze(event['bucket_name'])
        findings = analyzer.list_findings(event['analyzer_arn'], event['bucket_name'])
        
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
            
        # Update Terraform configurations
        update_success = policy_recommender.update_terraform_policies(recommendations)
        
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
