import os
import json
import boto3
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
from modules.iam_analyzer import IAMAnalyzer
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
        analyzer = IAMAnalyzer(region=os.environ.get('AWS_REGION', 'us-east-1'))
        policy_recommender = PolicyRecommender(
            github_token=get_github_token(),
            repo_name=os.environ.get('GITHUB_REPO'),
            region=os.environ.get('AWS_REGION', 'us-east-1')  # Add region parameter
        )
        
        # Get analyzer ARN from environment
        analyzer_arn = os.environ.get('ANALYZER_ARN')
        
        logger.info("Starting IAM resource analysis workflow")
        resources, findings, summary = analyzer.analyze_resources_from_s3(
            analyzer_arn=analyzer_arn,
            bucket_name=os.environ.get('S3_BUCKET'),
            prefix=os.environ.get('S3_PREFIX')
        )
        
        logger.info(f"Analysis complete: {summary.total_findings} findings for {len(resources)} resources")
        
        if not findings:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "No findings to analyze",
                    "status": "success",
                    "resources_analyzed": len(resources),
                    "findings_count": 0
                })
            }
        
        # Convert IAMResource objects to dictionaries for policy recommender compatibility
        resources_dict = []
        for resource in resources:
            resources_dict.append({
                "ResourceARN": resource.arn,
                "ResourceType": resource.resource_type.value,
                "ResourceName": resource.name,
                "tf_resource_name": resource.name.replace('-', '_')
            })
        
        logger.info(f"Fetching detailed findings for {len(findings)} findings")
        
        # Fetch detailed findings using the new method
        detailed_findings = policy_recommender.fetch_detailed_findings(analyzer_arn, findings)
        
        if not detailed_findings:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "No detailed findings available for analysis",
                    "status": "success",
                    "resources_analyzed": len(resources),
                    "findings_count": len(findings),
                    "detailed_findings_count": 0
                })
            }
        
        logger.info(f"Processing {len(detailed_findings)} detailed findings")
        
        # Process detailed findings and generate recommendations
        recommendations = policy_recommender.process_detailed_findings(detailed_findings, resources_dict)
        
        if not recommendations:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "No policy updates required - no unused permissions found",
                    "status": "success",
                    "resources_analyzed": len(resources),
                    "findings_count": len(findings),
                    "detailed_findings_count": len(detailed_findings),
                    "recommendations_count": 0
                })
            }
        
        logger.info(f"Generated {len(recommendations)} policy recommendations")
        
        # Create PR with policy updates using the new method
        pr_success = policy_recommender.create_policy_updates_pr(recommendations)
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Successfully processed findings and created PR" if pr_success else "Generated recommendations but failed to create PR",
                "status": "success" if pr_success else "partial_success",
                "resources_analyzed": len(resources),
                "findings_count": len(findings),
                "detailed_findings_count": len(detailed_findings),
                "recommendations_count": len(recommendations),
                "pr_created": pr_success,
                "finding_summary": {
                    "by_type": summary.findings_by_type,
                    "by_status": summary.findings_by_status
                },
                "unused_services_found": len(set().union(*[rec['unused_services'] for rec in recommendations.values()])),
                "total_unused_actions": sum(len(rec['unused_actions']) for rec in recommendations.values())
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
