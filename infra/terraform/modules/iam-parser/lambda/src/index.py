"""
Updated AWS Lambda function for IAM Access Analyzer integration with improved safety features.

This function now includes:
1. Proper configuration management with dry-run mode
2. Comprehensive error handling and validation
3. Safety checks and limits
4. Detailed logging and metrics
"""

import os
import json
import boto3
from typing import Dict, List, Tuple, Optional, Any
from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.metrics import MetricUnit

from modules.iam_analyzer import IAMAnalyzer
from modules.github_pr import GitHubPRHandler
from modules.improved_policy_recommender import ImprovedPolicyRecommender
from modules.configuration_manager import (
    ConfigurationManager, 
    LeastPrivilegeConfig, 
    ConfigurationError,
    load_config_from_env,
    create_dev_config
)
from modules.validation_integration import create_validation_config

# Initialize observability tools
logger = Logger(service="least-privilege-optimizer")
metrics = Metrics(namespace="LeastPrivilegeOptimizer")


class WorkflowError(Exception):
    """Raised when the workflow encounters an error"""
    pass


def load_configuration_safely(event: Dict) -> LeastPrivilegeConfig:
    """
    Load configuration with proper error handling and event-based overrides.
    
    Args:
        event: Lambda event payload that may contain configuration overrides
        
    Returns:
        Validated configuration object
        
    Raises:
        ConfigurationError: If configuration loading fails
    """
    logger.info("Loading configuration with safety checks")
    
    try:
        config_manager = ConfigurationManager()
        
        # Check for event-based configuration overrides
        event_config = event.get('config', {})
        
        # Special handling for dry-run mode
        if event.get('dry_run') is not None:
            event_config['dry_run'] = event['dry_run']
        
        # Load base configuration
        if event_config:
            logger.info(f"Applying event-based configuration overrides: {list(event_config.keys())}")
            config = config_manager.load_configuration(event_config)
        else:
            config = load_config_from_env()
        
        # Log the mode prominently
        if config.dry_run:
            logger.info("🔒 RUNNING IN DRY-RUN MODE - No changes will be made")
            metrics.add_metric(name="DryRunMode", unit=MetricUnit.Count, value=1)
        else:
            logger.warning("⚠️ RUNNING IN LIVE MODE - Real changes will be made!")
            metrics.add_metric(name="LiveMode", unit=MetricUnit.Count, value=1)
        
        return config
        
    except Exception as e:
        error_msg = f"Configuration loading failed: {str(e)}"
        logger.error(error_msg)
        raise ConfigurationError(error_msg) from e


def initialize_services_safely(config: LeastPrivilegeConfig) -> Tuple[IAMAnalyzer, GitHubPRHandler, ImprovedPolicyRecommender]:
    """
    Initialize services with proper error handling and configuration.
    
    Args:
        config: Configuration object
        
    Returns:
        Tuple of (IAMAnalyzer, GitHubPRHandler, ImprovedPolicyRecommender) instances
        
    Raises:
        WorkflowError: If service initialization fails
    """
    logger.info("Initializing services with improved safety features")
    
    try:
        # Initialize IAM Analyzer
        analyzer = IAMAnalyzer(region=config.aws_region)
        logger.info(f"✅ Initialized IAM Analyzer for region: {config.aws_region}")
        
        # Initialize GitHub PR Handler (only get token if not in dry-run mode)
        if config.dry_run:
            logger.info("🔒 Dry-run mode: Skipping GitHub token retrieval")
            github_handler = None
            logger.info("✅ GitHub handler initialization skipped (dry-run mode)")
        else:
            config_manager = ConfigurationManager(region=config.aws_region)
            github_token = config_manager.get_github_token(config)
            github_handler = GitHubPRHandler(
                github_token=github_token,
                repo_name=config.github_repo
            )
            logger.info(f"✅ Initialized GitHub handler for repo: {config.github_repo}")
        
        # Initialize Improved Policy Recommender with configuration
        policy_recommender = ImprovedPolicyRecommender(
            github_handler=github_handler,
            region=config.aws_region,
            config={
                'dry_run': config.dry_run,
                'environment': config.environment,
                'terraform_paths': config.terraform.file_paths,
                'max_actions_to_remove': config.safety.max_actions_per_user,
                'require_manual_approval': config.safety.require_manual_approval,
                'strict_validation': config.environment == 'production'
            }
        )
        logger.info("✅ Initialized Improved Policy Recommender with safety configuration")
        
        return analyzer, github_handler, policy_recommender
        
    except Exception as e:
        error_msg = f"Failed to initialize services: {str(e)}"
        logger.error(error_msg)
        raise WorkflowError(error_msg) from e


def analyze_iam_resources_safely(
    analyzer: IAMAnalyzer, 
    config: LeastPrivilegeConfig
) -> Tuple[List, List, object]:
    """
    Analyze IAM resources with comprehensive error handling and validation.
    
    Args:
        analyzer: IAMAnalyzer instance
        config: Configuration object
        
    Returns:
        Tuple of (resources, findings, summary)
        
    Raises:
        WorkflowError: If analysis fails
    """
    logger.info("Starting IAM resource analysis with validation")
    
    try:
        # Validate required configuration for analysis
        if not config.analyzer_arn:
            raise WorkflowError("analyzer_arn is required for resource analysis")
        
        if not config.s3_bucket:
            raise WorkflowError("s3_bucket is required for resource analysis")
        
        if not config.s3_prefix:
            raise WorkflowError("s3_prefix is required for resource analysis")
        
        # Perform analysis
        resources, findings, summary = analyzer.analyze_resources_from_s3(
            analyzer_arn=config.analyzer_arn,
            bucket_name=config.s3_bucket,
            prefix=config.s3_prefix
        )
        
        # Validate results
        if not resources:
            logger.warning("No IAM resources found in S3 data")
        
        # Log analysis results with safety context
        logger.info(f"Analysis completed successfully:")
        logger.info(f"  - Resources analyzed: {len(resources)}")
        logger.info(f"  - Total findings: {summary.total_findings}")
        logger.info(f"  - Findings by type: {summary.findings_by_type}")
        logger.info(f"  - Findings by status: {summary.findings_by_status}")
        
        # Safety check: too many findings might indicate a problem
        if summary.total_findings > 100:
            logger.warning(f"⚠️ Large number of findings ({summary.total_findings}) - review carefully")
        
        # Add metrics
        metrics.add_metric(name="ResourcesAnalyzed", unit=MetricUnit.Count, value=len(resources))
        metrics.add_metric(name="TotalFindings", unit=MetricUnit.Count, value=summary.total_findings)
        
        return resources, findings, summary
        
    except Exception as e:
        error_msg = f"IAM resource analysis failed: {str(e)}"
        logger.error(error_msg)
        metrics.add_metric(name="AnalysisErrors", unit=MetricUnit.Count, value=1)
        raise WorkflowError(error_msg) from e


def process_findings_safely(
    policy_recommender: ImprovedPolicyRecommender,
    findings: List,
    resources: List,
    config: LeastPrivilegeConfig
) -> Tuple[bool, Dict[str, Any]]:
    """
    Process findings with comprehensive safety checks and detailed results.
    
    Args:
        policy_recommender: ImprovedPolicyRecommender instance
        findings: List of Access Analyzer findings
        resources: List of IAM resources
        config: Configuration object
        
    Returns:
        Tuple of (success, detailed_results)
        
    Raises:
        WorkflowError: If processing fails catastrophically
    """
    logger.info("Processing findings with improved safety workflow")
    
    if not findings:
        logger.info("No findings to process")
        return True, {
            'success': True,
            'dry_run': config.dry_run,
            'users_analyzed': 0,
            'users_updated': 0,
            'message': 'No findings found - no policy updates required'
        }
    
    try:
        # Apply safety limits before processing
        limited_findings = findings[:config.safety.max_total_actions]
        if len(limited_findings) < len(findings):
            logger.warning(f"⚠️ Limited findings from {len(findings)} to {len(limited_findings)} based on safety configuration")
            metrics.add_metric(name="FindingsLimited", unit=MetricUnit.Count, value=len(findings) - len(limited_findings))
        
        # Convert resources to the format expected by policy recommender
        logger.info("Converting resource format for policy recommender")
        resources_dict = []
        for resource in resources:
            resources_dict.append({
                "arn": resource.arn,
                "ResourceARN": resource.arn,
                "resource_type": resource.resource_type,
                "ResourceType": resource.resource_type.value,
                "name": resource.name,
                "ResourceName": resource.name,
            })
        
        logger.info(f"Converted {len(resources_dict)} resources to dictionary format")
        
        # Process findings with the improved recommender
        logger.info("Starting improved policy recommendation workflow")
        success, detailed_results = policy_recommender.process_findings_and_create_pr(
            analyzer_arn=config.analyzer_arn,
            findings=limited_findings,
            resources=resources_dict
        )
        
        # Add configuration context to results
        detailed_results['config_summary'] = {
            'dry_run': config.dry_run,
            'environment': config.environment,
            'safety_limits': config.get_safety_limits()
        }
        
        # Log results based on mode
        if config.dry_run:
            logger.info("🔒 Dry-run completed successfully")
            if detailed_results.get('users_analyzed', 0) > 0:
                logger.info(f"Would have updated {detailed_results.get('users_updated', 0)} users")
        else:
            if success:
                logger.info("✅ Live workflow completed successfully")
                if detailed_results.get('pr_created'):
                    logger.info(f"Created PR: {detailed_results.get('pr_url')}")
            else:
                logger.error("❌ Live workflow failed")
        
        # Add metrics
        metrics.add_metric(name="UsersAnalyzed", unit=MetricUnit.Count, value=detailed_results.get('users_analyzed', 0))
        metrics.add_metric(name="UsersUpdated", unit=MetricUnit.Count, value=detailed_results.get('users_updated', 0))
        
        if success:
            metrics.add_metric(name="WorkflowSuccess", unit=MetricUnit.Count, value=1)
        else:
            metrics.add_metric(name="WorkflowFailures", unit=MetricUnit.Count, value=1)
        
        return success, detailed_results
        
    except Exception as e:
        error_msg = f"Failed to process findings: {str(e)}"
        logger.error(error_msg)
        metrics.add_metric(name="ProcessingErrors", unit=MetricUnit.Count, value=1)
        raise WorkflowError(error_msg) from e


def build_enhanced_response(
    success: bool,
    config: LeastPrivilegeConfig,
    resources_count: int,
    findings_count: int,
    detailed_results: Dict[str, Any],
    summary: object,
    request_id: str,
    error_message: Optional[str] = None
) -> Dict:
    """
    Build comprehensive Lambda response with safety information.
    
    Args:
        success: Whether the overall workflow succeeded
        config: Configuration object
        resources_count: Number of resources analyzed
        findings_count: Number of findings processed
        detailed_results: Detailed results from processing
        summary: Analysis summary object
        request_id: Lambda request ID
        error_message: Error message if workflow failed
        
    Returns:
        Enhanced Lambda response dictionary
    """
    # Build base response with enhanced information
    response_data = {
        "status": "success" if success else "failed",
        "request_id": request_id,
        "mode": "dry-run" if config.dry_run else "live",
        "environment": config.environment,
        "timestamp": detailed_results.get('timestamp', 'unknown'),
        "resources_analyzed": resources_count,
        "findings_count": findings_count,
        "safety_limits_applied": config.get_safety_limits()
    }
    
    # Add detailed results if available
    if detailed_results:
        response_data.update({
            "users_analyzed": detailed_results.get('users_analyzed', 0),
            "users_updated": detailed_results.get('users_updated', 0),
            "total_actions_removed": detailed_results.get('total_actions_removed', 0),
            "pr_created": detailed_results.get('pr_created', False),
            "pr_url": detailed_results.get('pr_url'),
            "warnings": detailed_results.get('warnings', []),
            "errors": detailed_results.get('errors', [])
        })
    
    # Add success-specific messaging
    if success:
        if config.dry_run:
            if detailed_results.get('users_analyzed', 0) > 0:
                response_data["message"] = f"🔒 Dry-run completed: Would update {detailed_results.get('users_updated', 0)} users"
            else:
                response_data["message"] = "🔒 Dry-run completed: No policy updates needed"
        else:
            if detailed_results.get('pr_created'):
                response_data["message"] = f"✅ Successfully updated policies and created PR"
            elif findings_count == 0:
                response_data["message"] = "✅ No findings found - no policy updates required"
            else:
                response_data["message"] = "✅ Completed analysis - no policy updates required"
        
        # Add finding summary if available
        if summary:
            response_data["finding_summary"] = {
                "total_findings": summary.total_findings,
                "by_type": summary.findings_by_type,
                "by_status": summary.findings_by_status
            }
    else:
        response_data["message"] = f"❌ Workflow failed: {error_message}"
        response_data["error"] = error_message
    
    # Add safety warnings for live mode
    if not config.dry_run:
        response_data["safety_notice"] = "⚠️ Live mode was used - real changes were made to policies"
    
    status_code = 200 if success else 500
    
    return {
        "statusCode": status_code,
        "body": json.dumps(response_data, indent=2, default=str)
    }


@logger.inject_lambda_context
@metrics.log_metrics
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    """
    Enhanced Lambda handler with comprehensive safety features and configuration management.
    
    This function orchestrates the improved workflow:
    1. Load configuration with safety checks and dry-run mode
    2. Initialize services with proper error handling
    3. Analyze IAM resources with validation
    4. Process findings with safety limits and detailed results
    
    Event parameters:
    - dry_run (bool): Force dry-run mode regardless of configuration
    - config (dict): Configuration overrides
    
    Args:
        event: Lambda event payload
        context: Lambda context object
        
    Returns:
        Enhanced response dictionary with detailed results
    """
    logger.info("🚀 Starting enhanced IAM least privilege optimization workflow")
    logger.info(f"Request ID: {context.aws_request_id}")
    logger.info(f"Function Name: {context.function_name}")
    logger.info(f"Remaining Time: {context.get_remaining_time_in_millis()}ms")
    
    # Initialize tracking variables
    config = None
    resources_count = 0
    findings_count = 0
    detailed_results = {}
    summary = None
    
    try:
        # Step 1: Load configuration with safety checks
        logger.info("=== Step 1: Loading Configuration with Safety Checks ===")
        config = load_configuration_safely(event)
        
        # Step 2: Initialize services
        logger.info("=== Step 2: Initializing Services ===")
        analyzer, github_handler, policy_recommender = initialize_services_safely(config)
        
        # Step 3: Analyze IAM resources with validation
        logger.info("=== Step 3: Analyzing IAM Resources ===")
        resources, findings, summary = analyze_iam_resources_safely(analyzer, config)
        resources_count = len(resources)
        findings_count = len(findings)
        
        # Step 4: Process findings with improved safety
        logger.info("=== Step 4: Processing Findings with Safety Checks ===")
        process_success, detailed_results = process_findings_safely(
            policy_recommender, findings, resources, config
        )
        
        # Workflow completed
        mode_msg = "🔒 DRY-RUN" if config.dry_run else "⚠️ LIVE"
        logger.info(f"=== {mode_msg} Workflow Completed ===")
        logger.info(f"Final Results:")
        logger.info(f"  - Mode: {mode_msg}")
        logger.info(f"  - Resources: {resources_count}")
        logger.info(f"  - Findings: {findings_count}")
        logger.info(f"  - Users Analyzed: {detailed_results.get('users_analyzed', 0)}")
        logger.info(f"  - Users Updated: {detailed_results.get('users_updated', 0)}")
        logger.info(f"  - Success: {process_success}")
        
        return build_enhanced_response(
            success=process_success,
            config=config,
            resources_count=resources_count,
            findings_count=findings_count,
            detailed_results=detailed_results,
            summary=summary,
            request_id=context.aws_request_id
        )
        
    except (ConfigurationError, WorkflowError) as e:
        logger.error(f"Workflow failed with known error: {str(e)}")
        metrics.add_metric(name="WorkflowErrors", unit=MetricUnit.Count, value=1)
        
        # Use safe defaults for config if it failed to load
        safe_config = config or create_dev_config()
        
        return build_enhanced_response(
            success=False,
            config=safe_config,
            resources_count=resources_count,
            findings_count=findings_count,
            detailed_results=detailed_results,
            summary=summary,
            request_id=context.aws_request_id,
            error_message=str(e)
        )
        
    except Exception as e:
        logger.exception("Unexpected error in workflow")
        metrics.add_metric(name="UnexpectedErrors", unit=MetricUnit.Count, value=1)
        
        # Use safe defaults for config if it failed to load
        safe_config = config or create_dev_config()
        
        return build_enhanced_response(
            success=False,
            config=safe_config,
            resources_count=resources_count,
            findings_count=findings_count,
            detailed_results=detailed_results,
            summary=summary,
            request_id=context.aws_request_id,
            error_message=f"Unexpected error: {str(e)}"
        )


# Enhanced testing support
if __name__ == "__main__":
    # Mock context for testing
    class MockContext:
        aws_request_id = "test-request-123"
        function_name = "test-function"
        
        def get_remaining_time_in_millis(self):
            return 300000  # 5 minutes
    
    # Example test events
    
    # Dry-run test
    dry_run_event = {
        "dry_run": True,
        "config": {
            "analyzer_arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test",
            "s3_bucket": "test-bucket",
            "s3_prefix": "iam-data",
            "github_repo": "test-org/test-repo"
        }
    }
    
    # Live mode test (requires real configuration)
    # live_event = {
    #     "dry_run": False,
    #     "config": {
    #         "analyzer_arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/real",
    #         "s3_bucket": "real-bucket", 
    #         "s3_prefix": "iam-data",
    #         "github_repo": "real-org/real-repo"
    #     }
    # }
    
    test_context = MockContext()
    
    print("🧪 Running dry-run test...")
    result = lambda_handler(dry_run_event, test_context)
    print(json.dumps(result, indent=2))