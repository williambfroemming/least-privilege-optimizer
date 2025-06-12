import os
import json
import pytest
import warnings
from dotenv import load_dotenv
import sys
sys.path.append('..')
from src.modules.iam_analyzer import Analyzer
from src.modules.github_pr import GitHubPRHandler
from src.modules.policy_recommender import PolicyRecommender
from src.index import lambda_handler

# Filter out the specific botocore datetime warning
warnings.filterwarnings(
    "ignore",
    message="datetime.datetime.utcnow() is deprecated",
    category=DeprecationWarning,
    module="botocore.auth"
)

# Load environment variables from .env file
load_dotenv()

# Set up logging
import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

@pytest.fixture
def analyzer():
    logger.info("Creating analyzer instance with region: %s", os.getenv('AWS_REGION'))
    return Analyzer(region=os.getenv('AWS_REGION'))

@pytest.fixture
def github_handler():
    logger.info("Creating GitHub handler for repo: %s", os.getenv('GITHUB_REPO'))
    return GitHubPRHandler(
        github_token=os.getenv('GITHUB_TOKEN'),
        repo_name=os.getenv('GITHUB_REPO')
    )

@pytest.fixture
def policy_recommender():
    logger.info("Creating policy recommender instance")
    return PolicyRecommender(
        github_token=os.getenv('GITHUB_TOKEN'),
        repo_name=os.getenv('GITHUB_REPO')
    )

@pytest.fixture
def sample_resources():
    return [
        {
            "ResourceARN": "arn:aws:iam::904610147891:user/static-parser-test-user",
            "ResourceType": "AWS::IAM::User",
            "ResourceName": "static-parser-test-user",
            "tf_resource_name": "test_user"
        }
    ]

@pytest.fixture
def sample_findings():
    return [
        {
            "id": "test-finding-1",
            "resource": {
                "arn": "arn:aws:iam::904610147891:user/static-parser-test-user",
                "type": "AWS::IAM::User",
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:*"],
                            "Resource": "*"
                        }
                    ]
                }
            },
            "analyzedPolicy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": ["arn:aws:s3:::example-bucket/*"]
                    }
                ]
            }
        }
    ]

def test_analyzer_list_findings(analyzer):
    """Test listing findings from IAM Access Analyzer"""
    logger.info("Starting test_analyzer_list_findings")
    logger.info("Using analyzer ARN: %s", os.getenv('ANALYZER_ARN'))
    findings = analyzer.list_findings(os.getenv('ANALYZER_ARN'))
    assert isinstance(findings, list)
    logger.info("Found %d findings", len(findings))
    for i, finding in enumerate(findings[:3], 1):  # Log first 3 findings
        logger.info("Finding %d: Resource Type: %s, ARN: %s", 
                   i, 
                   finding.get('resource', {}).get('type'),
                   finding.get('resource', {}).get('arn'))

def test_github_pr_creation(github_handler):
    """Test creating a GitHub PR with a sample policy"""
    logger.info("Starting test_github_pr_creation")
    logger.info("Creating PR with sample IAM policy")
    result = github_handler.create_pull_request(
        title="Test IAM Policy Updates",
        body="Integration test - creating PR with sample IAM policy",
        policy_changes={
            "policies/test-policy.json": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::test-bucket/*"
                }]
            }
        }
    )
    assert result["status"] == "success"
    logger.info("PR created successfully: %s", result.get('pr_url'))

def test_github_pr_creation_with_complex_policy(github_handler):
    """Test creating a GitHub PR with a complex IAM policy"""
    logger.info("Starting test_github_pr_creation_with_complex_policy")
    logger.info("Creating PR with complex IAM policy")
    result = github_handler.create_pull_request(
        title="Update Data Engineer IAM Policy",
        body="Integration test - updating data engineer policy with least privilege recommendations",
        policy_changes={
            "policies/data-engineer-policy.json": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DataLakeAccess",
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:PutObject",
                            "s3:ListBucket",
                            "athena:StartQueryExecution",
                            "athena:GetQueryExecution",
                            "athena:GetQueryResults",
                            "glue:GetTables",
                            "glue:GetDatabases",
                            "logs:DescribeLogGroups"
                        ],
                        "Resource": [
                            "arn:aws:s3:::ucb-capstone-bucket/*",
                            "arn:aws:s3:::ucb-capstone-athena-results/*",
                            "arn:aws:athena:*:*:workgroup/*",
                            "arn:aws:glue:*:*:catalog",
                            "arn:aws:glue:*:*:database/*",
                            "arn:aws:glue:*:*:table/*/*",
                            "arn:aws:logs:*:*:log-group:*"
                        ]
                    },
                    {
                        "Sid": "EC2ReadAccess",
                        "Effect": "Allow",
                        "Action": [
                            "ec2:DescribeInstances",
                            "ec2:DescribeVolumes",
                            "ec2:DescribeSnapshots"
                        ],
                        "Resource": "*"
                    }
                ]
            }
        }
    )
    assert result["status"] == "success"
    logger.info("PR with complex policy created successfully: %s", result.get('pr_url'))

def test_full_integration():
    """Test the complete flow from analyzing policies to creating a PR"""
    logger.info("Starting test_full_integration")
    
    if not os.getenv('ANALYZER_ARN') or not os.getenv('TEST_BUCKET'):
        logger.warning("Skipping test: Required environment variables not set")
        logger.info("ANALYZER_ARN: %s", os.getenv('ANALYZER_ARN'))
        logger.info("TEST_BUCKET: %s", os.getenv('TEST_BUCKET'))
        pytest.skip("Required environment variables ANALYZER_ARN or TEST_BUCKET not set")
    
    event = {
        "analyzer_arn": os.getenv('ANALYZER_ARN'),
        "bucket_name": os.getenv('TEST_BUCKET'),
        "pr_title": "Integration Test - IAM Policy Updates",
        "pr_body": "Automated PR from integration test"
    }
    logger.info("Created event payload: %s", json.dumps(event))
    
    class MockContext:
        function_name = "test-function"
        memory_limit_in_mb = 128
        invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-function"
        aws_request_id = "test-request-id"
    
    logger.info("Calling lambda handler")
    result = lambda_handler(event, MockContext())
    logger.info("Lambda handler response: %s", json.dumps(result))
    
    assert result["statusCode"] == 200
    response_body = json.loads(result["body"])
    assert response_body["status"] in ["success", "partial_success"]
    logger.info("Integration test completed with status: %s", response_body["status"])

def test_full_integration_with_complex_policy():
    """Test the complete flow from analyzing policies to creating a PR with complex policies"""
    logger.info("Starting test_full_integration_with_complex_policy")
    
    if not os.getenv('ANALYZER_ARN') or not os.getenv('TEST_BUCKET'):
        logger.warning("Skipping test: Required environment variables not set")
        pytest.skip("Required environment variables ANALYZER_ARN or TEST_BUCKET not set")
    
    event = {
        "analyzer_arn": os.getenv('ANALYZER_ARN'),
        "bucket_name": os.getenv('TEST_BUCKET'),
        "pr_title": "Update Data Engineer Permissions",
        "pr_body": "Automated PR for data engineer policy updates based on Access Analyzer findings",
        "base_branch": "main",
        "head_branch": "data-engineer-policy-updates"
    }
    logger.info("Created event payload for complex policy: %s", json.dumps(event))
    
    class MockContext:
        function_name = "test-function"
        memory_limit_in_mb = 128
        invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-function"
        aws_request_id = "test-request-id"
    
    logger.info("Calling lambda handler for complex policy")
    result = lambda_handler(event, MockContext())
    logger.info("Lambda handler response for complex policy: %s", json.dumps(result))
    
    assert result["statusCode"] == 200
    response_body = json.loads(result["body"])
    assert response_body["status"] in ["success", "partial_success"]
    logger.info("Complex policy integration test completed with status: %s", response_body["status"])

def test_analyzer_resource_fetching(analyzer):
    """Test fetching resources from S3"""
    logger.info("Starting test_analyzer_resource_fetching")
    
    if not os.getenv('TEST_BUCKET'):
        logger.warning("Skipping test: TEST_BUCKET not set")
        pytest.skip("TEST_BUCKET environment variable not set")
    
    logger.info("Fetching resources from bucket: %s", os.getenv('TEST_BUCKET'))
    resources = analyzer.fetch_resources_to_analyze(os.getenv('TEST_BUCKET'))
    assert isinstance(resources, list)
    
    if resources:
        logger.info("Successfully fetched %d resources", len(resources))
        for i, resource in enumerate(resources[:3], 1):  # Log first 3 resources
            logger.info("Resource %d: Type: %s, Name: %s, ARN: %s",
                       i,
                       resource.get('ResourceType'),
                       resource.get('ResourceName'),
                       resource.get('ResourceARN'))
    else:
        logger.warning("No resources found in bucket")

def test_policy_recommender_processing(policy_recommender, sample_findings, sample_resources):
    """Test processing findings and generating recommendations"""
    logger.info("Starting test_policy_recommender_processing")
    logger.info("Processing %d findings for %d resources", 
                len(sample_findings), len(sample_resources))
    
    recommendations = policy_recommender.process_findings(sample_findings, sample_resources)
    assert isinstance(recommendations, dict)
    assert len(recommendations) > 0
    
    logger.info("Generated %d recommendations", len(recommendations))
    for key, recommendation in recommendations.items():
        logger.info("Recommendation for %s:", key)
        logger.info("  Resource Type: %s", recommendation['resource_type'])
        logger.info("  Resource Name: %s", recommendation['resource_name'])
        if 'current_policy' in recommendation:
            logger.info("  Current Policy Actions: %s", 
                       json.dumps(recommendation['current_policy'].get('Statement', []))[:100] + "...")
        if 'recommended_policy' in recommendation:
            logger.info("  Recommended Policy Actions: %s",
                       json.dumps(recommendation['recommended_policy'].get('Statement', []))[:100] + "...")

def test_full_analyzer_recommender_flow():
    """Test the complete flow from analysis to recommendations"""
    logger.info("Starting test_full_analyzer_recommender_flow")
    
    if not os.getenv('ANALYZER_ARN') or not os.getenv('TEST_BUCKET'):
        logger.warning("Skipping test: Required environment variables not set")
        pytest.skip("Missing required environment variables")
    
    event = {
        "analyzer_arn": os.getenv('ANALYZER_ARN'),
        "bucket_name": os.getenv('TEST_BUCKET'),
        "pr_title": "Test Policy Updates",
        "pr_body": "Integration test - policy updates"
    }
    logger.info("Created event: %s", json.dumps(event))
    
    class MockContext:
        function_name = "test-function"
        memory_limit_in_mb = 128
        invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-function"
        aws_request_id = "test-request-id"
    
    logger.info("Executing lambda handler")
    result = lambda_handler(event, MockContext())
    logger.info("Lambda response: %s", json.dumps(result))
    
    response_body = json.loads(result["body"])
    if result["statusCode"] == 200:
        logger.info("Test completed successfully")
        if "recommendations_count" in response_body:
            logger.info("Generated %d recommendations", response_body["recommendations_count"])
    else:
        logger.warning("Test completed with error: %s", response_body.get('error'))

def test_recommender_terraform_updates(policy_recommender, sample_findings, sample_resources):
    """Test terraform policy update functionality"""
    logger.info("Starting test_recommender_terraform_updates")
    recommendations = policy_recommender.process_findings(sample_findings, sample_resources)
    assert isinstance(recommendations, dict)
    
    logger.info("Attempting to update terraform policies")
    result = policy_recommender.update_terraform_policies(recommendations)
    assert isinstance(result, bool)
    logger.info("Terraform update test completed")

if __name__ == "__main__":
    # This allows running the integration tests directly
    pytest.main([__file__, "-v"])