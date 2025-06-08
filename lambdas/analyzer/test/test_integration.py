import os
import json
import pytest
import warnings
from dotenv import load_dotenv
import sys
sys.path.append('..')  # Add parent directory to Python path
from modules.iam_analyzer import AccessAnalyzerWrapper
from modules.github_pr import GitHubPRHandler
from index import lambda_handler

# Filter out the specific botocore datetime warning
warnings.filterwarnings(
    "ignore",
    message="datetime.datetime.utcnow() is deprecated",
    category=DeprecationWarning,
    module="botocore.auth"
)

# Load environment variables from .env file
load_dotenv()

@pytest.fixture
def analyzer():
    return AccessAnalyzerWrapper(region=os.getenv('AWS_REGION'))

@pytest.fixture
def github_handler():
    return GitHubPRHandler(
        github_token=os.getenv('GITHUB_TOKEN'),
        repo_name=os.getenv('GITHUB_REPO')
    )

def test_analyzer_list_findings(analyzer):
    """Test listing findings from IAM Access Analyzer"""
    findings = analyzer.list_findings(os.getenv('ANALYZER_ARN'))
    assert isinstance(findings, list)
    # Print findings for debugging
    print(f"Found {len(findings)} findings")

def test_github_pr_creation(github_handler):
    """Test creating a GitHub PR with a sample policy"""
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
    assert "pr_number" in result
    assert "pr_url" in result
    print(f"Created PR: {result['pr_url']}")

def test_github_pr_creation_with_complex_policy(github_handler):
    """Test creating a GitHub PR with a complex IAM policy"""
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
    assert "pr_number" in result
    assert "pr_url" in result
    print(f"Created PR with complex policy: {result['pr_url']}")

def test_full_integration():
    """Test the complete flow from analyzing policies to creating a PR"""
    # Create event for lambda handler
    event = {
        "analyzer_arn": os.getenv('ANALYZER_ARN'),
        "pr_title": "Integration Test - IAM Policy Updates",
        "pr_body": "Automated PR from integration test"
    }
    
    # Create mock context (still needed for aws-lambda-powertools)
    class MockContext:
        function_name = "test-function"
        memory_limit_in_mb = 128
        invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-function"
        aws_request_id = "test-request-id"
    
    result = lambda_handler(event, MockContext())
    
    assert result["statusCode"] == 200
    response_body = json.loads(result["body"])
    assert response_body["status"] == "success"
    print(f"Integration test complete. PR created at: {response_body.get('pr_url')}")

def test_full_integration_with_complex_policy():
    """Test the complete flow from analyzing policies to creating a PR with complex policies"""
    event = {
        "analyzer_arn": os.getenv('ANALYZER_ARN'),
        "pr_title": "Update Data Engineer Permissions",
        "pr_body": "Automated PR for data engineer policy updates based on Access Analyzer findings",
        "base_branch": "main",
        "head_branch": "data-engineer-policy-updates"
    }
    
    # Create mock context
    class MockContext:
        function_name = "test-function"
        memory_limit_in_mb = 128
        invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-function"
        aws_request_id = "test-request-id"
    
    result = lambda_handler(event, MockContext())
    
    assert result["statusCode"] == 200
    response_body = json.loads(result["body"])
    assert response_body["status"] == "success"
    print(f"Complex policy integration test complete. PR created at: {response_body.get('pr_url')}")

if __name__ == "__main__":
    # This allows running the integration tests directly
    pytest.main([__file__, "-v"])