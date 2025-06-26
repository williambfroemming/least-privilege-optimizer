"""
AWS Lambda function for IAM Access Analyzer integration and least privilege policy optimization.

This function:
1. Analyzes IAM resources and findings from Access Analyzer
2. Generates policy recommendations for unused permissions
3. Creates GitHub PRs with Terraform policy updates
4. Works with all users found in S3 data
"""

import os
import json
import boto3
from typing import Dict, List, Tuple, Optional
from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.metrics import MetricUnit

from modules.iam_analyzer import IAMAnalyzer
from modules.policy_recommender import PolicyRecommender

# Initialize observability tools
logger = Logger(service="least-privilege-optimizer")
metrics = Metrics(namespace="LeastPrivilegeOptimizer")


class ConfigurationError(Exception):
    """Raised when configuration is invalid or incomplete"""
    pass


class WorkflowError(Exception):
    """Raised when the workflow encounters an error"""
    pass


def load_configuration() -> Dict[str, str]:
    """
    Load and validate configuration from environment variables and SSM.
    
    Returns:
        Dictionary containing all required configuration values
        
    Raises:
        ConfigurationError: If required configuration is missing or invalid
    """
    logger.info("Loading configuration from environment and SSM")
    
    # Required environment variables
    required_env_vars = {
        'GITHUB_REPO': 'GitHub repository name (owner/repo)',
        'ANALYZER_ARN': 'AWS Access Analyzer ARN',
        'S3_BUCKET': 'S3 bucket containing IAM resource data',
        'S3_PREFIX': 'S3 prefix for IAM resource files'
    }
    
    config = {}
    missing_vars = []
    
    # Check environment variables
    for var, description in required_env_vars.items():
        value = os.getenv(var)
        if not value:
            missing_vars.append(f"{var} ({description})")
        else:
            config[var] = value
            logger.debug(f"Loaded {var}: {value[:20]}..." if len(value) > 20 else f"Loaded {var}: {value}")
    
    # Add optional configuration
    config['AWS_REGION'] = os.getenv('AWS_REGION', 'us-east-1')
    
    if missing_vars:
        error_msg = f"Missing required environment variables: {', '.join(missing_vars)}"
        logger.error(error_msg)
        raise ConfigurationError(error_msg)
    
    # Load GitHub token from SSM
    try:
        logger.info("Retrieving GitHub token from SSM Parameter Store")
        ssm = boto3.client('ssm', region_name=config['AWS_REGION'])
        github_token_ssm_path = os.getenv('GITHUB_TOKEN_SSM_PATH', '/github-token')
        response = ssm.get_parameter(Name=github_token_ssm_path, WithDecryption=True)
        config['GITHUB_TOKEN'] = response['Parameter']['Value']
        logger.info("Successfully retrieved GitHub token from SSM")
    except Exception as e:
        error_msg = f"Failed to retrieve GitHub token from SSM: {str(e)}"
        logger.error(error_msg)
        raise ConfigurationError(error_msg)
    
    logger.info("Configuration loaded successfully")
    return config


def initialize_services(config: Dict[str, str]) -> Tuple[IAMAnalyzer, PolicyRecommender]:
    """
    Initialize the IAM analyzer and policy recommender services.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Tuple of (IAMAnalyzer, PolicyRecommender) instances
    """
    logger.info("Initializing services")
    
    try:
        # Initialize IAM Analyzer
        analyzer = IAMAnalyzer(region=config['AWS_REGION'])
        logger.info(f"Initialized IAM Analyzer for region: {config['AWS_REGION']}")
        
        # Initialize Policy Recommender
        policy_recommender = PolicyRecommender(
            github_token=config['GITHUB_TOKEN'],
            repo_name=config['GITHUB_REPO'],
            region=config['AWS_REGION']
        )
        logger.info(f"Initialized Policy Recommender for repo: {config['GITHUB_REPO']}")
        
        return analyzer, policy_recommender
        
    except Exception as e:
        error_msg = f"Failed to initialize services: {str(e)}"
        logger.error(error_msg)
        raise WorkflowError(error_msg)


def analyze_iam_resources(analyzer: IAMAnalyzer, config: Dict[str, str]) -> Tuple[List, List, object]:
    """
    Analyze IAM resources and findings from S3 data.
    
    Args:
        analyzer: IAMAnalyzer instance
        config: Configuration dictionary
        
    Returns:
        Tuple of (resources, findings, summary)
        
    Raises:
        WorkflowError: If analysis fails
    """
    logger.info("Starting IAM resource analysis")
    
    try:
        resources, findings, summary = analyzer.analyze_resources_from_s3(
            analyzer_arn=config['ANALYZER_ARN'],
            bucket_name=config['S3_BUCKET'],
            prefix=config['S3_PREFIX']
        )
        
        # Log analysis results
        logger.info(f"Analysis completed successfully:")
        logger.info(f"  - Resources analyzed: {len(resources)}")
        logger.info(f"  - Total findings: {summary.total_findings}")
        logger.info(f"  - Findings by type: {summary.findings_by_type}")
        logger.info(f"  - Findings by status: {summary.findings_by_status}")
        
        # Add metrics
        metrics.add_metric(name="ResourcesAnalyzed", unit=MetricUnit.Count, value=len(resources))
        metrics.add_metric(name="TotalFindings", unit=MetricUnit.Count, value=summary.total_findings)
        
        return resources, findings, summary
        
    except Exception as e:
        error_msg = f"IAM resource analysis failed: {str(e)}"
        logger.error(error_msg)
        metrics.add_metric(name="AnalysisErrors", unit=MetricUnit.Count, value=1)
        raise WorkflowError(error_msg)


def process_findings_and_generate_recommendations(
    policy_recommender: PolicyRecommender,
    findings: List,
    resources: List,
    config: Dict[str, str]
) -> Dict:
    """
    Process Access Analyzer findings and generate policy recommendations.
    
    Args:
        policy_recommender: PolicyRecommender instance
        findings: List of Access Analyzer findings
        resources: List of IAM resources
        config: Configuration dictionary
        
    Returns:
        Dictionary of policy recommendations
        
    Raises:
        WorkflowError: If processing fails
    """
    logger.info("Processing findings and generating recommendations")
    
    if not findings:
        logger.info("No findings to process")
        return {}
    
    try:
        # Convert resources to the format expected by PolicyRecommender
        logger.info("Converting resource format for policy recommender")
        resources_dict = []
        for resource in resources:
            resources_dict.append({
                "ResourceARN": resource.arn,
                "ResourceType": resource.resource_type.value,
                "ResourceName": resource.name,
                "tf_resource_name": resource.name.replace('-', '_')
            })
        
        logger.info(f"Converted {len(resources_dict)} resources to dictionary format")
        
        # Fetch detailed findings (with robust error handling)
        logger.info(f"Fetching detailed findings for {len(findings)} findings")
        detailed_findings = policy_recommender.fetch_detailed_findings(
            analyzer_arn=config['ANALYZER_ARN'],
            findings=findings
        )
        
        if not detailed_findings:
            logger.info("No detailed findings available for processing")
            return {}
        
        logger.info(f"Successfully fetched {len(detailed_findings)} detailed findings")
        
        # Process findings and generate recommendations
        logger.info("Generating policy recommendations from detailed findings")
        recommendations = policy_recommender.process_detailed_findings(
            detailed_findings, 
            resources_dict
        )
        
        if recommendations:
            logger.info(f"Generated {len(recommendations)} policy recommendations:")
            for resource_key, rec in recommendations.items():
                logger.info(f"  - {resource_key}: {len(rec.get('unused_actions', []))} unused actions")
        else:
            logger.info("No policy recommendations generated")
        
        # Add metrics
        metrics.add_metric(name="DetailedFindings", unit=MetricUnit.Count, value=len(detailed_findings))
        metrics.add_metric(name="Recommendations", unit=MetricUnit.Count, value=len(recommendations))
        
        return recommendations
        
    except Exception as e:
        error_msg = f"Failed to process findings and generate recommendations: {str(e)}"
        logger.error(error_msg)
        metrics.add_metric(name="ProcessingErrors", unit=MetricUnit.Count, value=1)
        raise WorkflowError(error_msg)


def create_github_pr(policy_recommender: PolicyRecommender, recommendations: Dict) -> bool:
    """
    Create a GitHub PR with policy updates.
    
    Args:
        policy_recommender: PolicyRecommender instance
        recommendations: Dictionary of policy recommendations
        
    Returns:
        True if PR was created successfully, False otherwise
    """
    logger.info("Creating GitHub PR with policy updates")
    
    if not recommendations:
        logger.info("No recommendations to create PR for")
        return True
    
    try:
        pr_success = policy_recommender.create_policy_updates_pr(recommendations)
        
        if pr_success:
            logger.info("Successfully created GitHub PR with policy updates")
            metrics.add_metric(name="PRsCreated", unit=MetricUnit.Count, value=1)
        else:
            logger.error("Failed to create GitHub PR")
            metrics.add_metric(name="PRCreationFailures", unit=MetricUnit.Count, value=1)
        
        return pr_success
        
    except Exception as e:
        error_msg = f"Failed to create GitHub PR: {str(e)}"
        logger.error(error_msg)
        metrics.add_metric(name="PRCreationErrors", unit=MetricUnit.Count, value=1)
        return False


def build_response(
    success: bool,
    resources_count: int,
    findings_count: int,
    detailed_findings_count: int,
    recommendations: Dict,
    pr_created: bool,
    summary: object,
    request_id: str,
    error_message: Optional[str] = None
) -> Dict:
    """
    Build the Lambda response payload.
    """
    # Calculate metrics
    recommendations_count = len(recommendations)
    total_unused_actions = sum(
        len(rec.get('unused_actions', []))
        for rec in recommendations.values()
        if isinstance(rec.get('unused_actions'), list)
    )
    
    # Build base response
    response_data = {
        "status": "success" if success else "failed",
        "request_id": request_id,
        "resources_analyzed": resources_count,
        "findings_count": findings_count,
        "detailed_findings_count": detailed_findings_count,
        "recommendations_count": recommendations_count,
        "total_unused_actions": total_unused_actions,
        "pr_created": pr_created
    }
    
    # Add success-specific data
    if success:
        if recommendations_count > 0:
            response_data["message"] = f"Successfully generated {recommendations_count} policy recommendations and created PR"
        else:
            response_data["message"] = "No policy updates required - no unused permissions found for target resources"
        
        # Add finding summary if available
        if summary:
            response_data["finding_summary"] = {
                "by_type": summary.findings_by_type,
                "by_status": summary.findings_by_status
            }
        
        # Add recommendation details
        if recommendations:
            response_data["recommendations"] = [
                {
                    "resource": key,
                    "finding_id": rec.get('finding_id'),
                    "unused_actions_count": len(rec.get('unused_actions', []))
                }
                for key, rec in recommendations.items()
            ]
    else:
        response_data["message"] = f"Workflow failed: {error_message}"
        response_data["error"] = error_message
    
    status_code = 200 if success else 500
    
    return {
        "statusCode": status_code,
        "body": json.dumps(response_data, indent=2)
    }


@logger.inject_lambda_context
@metrics.log_metrics
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    """
    Main Lambda handler for IAM least privilege optimization workflow.
    """
    logger.info("Starting IAM least privilege optimization workflow")
    logger.info(f"Request ID: {context.aws_request_id}")
    logger.info(f"Function Name: {context.function_name}")
    logger.info(f"Remaining Time: {context.get_remaining_time_in_millis()}ms")
    
    # Initialize tracking variables
    resources_count = 0
    findings_count = 0
    detailed_findings_count = 0
    recommendations = {}
    pr_created = False
    summary = None
    
    try:
        # Step 1: Load configuration
        logger.info("=== Step 1: Loading Configuration ===")
        config = load_configuration()
        
        # Step 2: Initialize services
        logger.info("=== Step 2: Initializing Services ===")
        analyzer, policy_recommender = initialize_services(config)
        
        # Step 3: Analyze IAM resources
        logger.info("=== Step 3: Analyzing IAM Resources ===")
        resources, findings, summary = analyze_iam_resources(analyzer, config)
        resources_count = len(resources)
        findings_count = len(findings)
        
        # Step 4: Process findings and generate recommendations
        logger.info("=== Step 4: Processing Findings ===")
        recommendations = process_findings_and_generate_recommendations(
            policy_recommender, findings, resources, config
        )
        detailed_findings_count = len([f for f in findings if f])  # Count non-empty findings
        
        # Step 5: Create GitHub PR
        logger.info("=== Step 5: Creating GitHub PR ===")
        pr_created = create_github_pr(policy_recommender, recommendations)
        
        # Workflow completed successfully
        logger.info("=== Workflow Completed Successfully ===")
        logger.info(f"Final Results:")
        logger.info(f"  - Resources: {resources_count}")
        logger.info(f"  - Findings: {findings_count}")
        logger.info(f"  - Recommendations: {len(recommendations)}")
        logger.info(f"  - PR Created: {pr_created}")
        
        return build_response(
            success=True,
            resources_count=resources_count,
            findings_count=findings_count,
            detailed_findings_count=detailed_findings_count,
            recommendations=recommendations,
            pr_created=pr_created,
            summary=summary,
            request_id=context.aws_request_id
        )
        
    except (ConfigurationError, WorkflowError) as e:
        logger.error(f"Workflow failed with known error: {str(e)}")
        metrics.add_metric(name="WorkflowErrors", unit=MetricUnit.Count, value=1)
        
        return build_response(
            success=False,
            resources_count=resources_count,
            findings_count=findings_count,
            detailed_findings_count=detailed_findings_count,
            recommendations=recommendations,
            pr_created=pr_created,
            summary=summary,
            request_id=context.aws_request_id,
            error_message=str(e)
        )
        
    except Exception as e:
        logger.exception("Unexpected error in workflow")
        metrics.add_metric(name="UnexpectedErrors", unit=MetricUnit.Count, value=1)
        
        return build_response(
            success=False,
            resources_count=resources_count,
            findings_count=findings_count,
            detailed_findings_count=detailed_findings_count,
            recommendations=recommendations,
            pr_created=pr_created,
            summary=summary,
            request_id=context.aws_request_id,
            error_message=f"Unexpected error: {str(e)}"
        )