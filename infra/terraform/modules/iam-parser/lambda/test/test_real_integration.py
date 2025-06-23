"""
Real AWS Integration Tests for IAM Analyzer Lambda Function

This test suite runs the lambda function locally against real AWS resources
and outputs the exact content that would be created in GitHub PRs.

Setup Instructions:
1. Copy .env.example to .env and fill in your real AWS credentials
2. Ensure you have an AWS Access Analyzer configured
3. Ensure you have IAM resources in your S3 bucket
4. Run: python -m pytest test_real_integration.py -v -s
"""

import pytest
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any
from unittest.mock import Mock, patch
from datetime import datetime
import boto3
from dotenv import load_dotenv

# Add the src directory to the path for local testing
test_dir = Path(__file__).parent
src_dir = test_dir / ".." / "src"
sys.path.insert(0, str(src_dir))

# Load environment variables from .env file - look in parent directory
env_path = test_dir / ".." / ".env"  # Changed from test_dir / ".env"
if env_path.exists():
    load_dotenv(env_path)
else:
    pytest.skip("No .env file found. Copy .env.example to .env and configure it.", allow_module_level=True)

# Import lambda function and modules
from index import lambda_handler, validate_environment, get_github_token
from modules.iam_analyzer import IAMAnalyzer, AnalyzerError
from modules.policy_recommender import PolicyRecommender
from modules.github_pr import GitHubPRHandler


class TestRealAWSIntegration:
    """Real AWS integration tests for the complete lambda workflow"""
    
    @pytest.fixture(autouse=True)
    def setup_aws_environment(self):
        """Setup AWS environment variables for testing"""
        required_env_vars = {
            'AWS_REGION': os.getenv('AWS_REGION', 'us-east-1'),
            'ANALYZER_ARN': os.getenv('ANALYZER_ARN'),
            'S3_BUCKET': os.getenv('S3_BUCKET'),
            'S3_PREFIX': os.getenv('S3_PREFIX'),
            'GITHUB_REPO': os.getenv('GITHUB_REPO'),
            'LOG_LEVEL': os.getenv('LOG_LEVEL', 'DEBUG'),
            'ENVIRONMENT': os.getenv('ENVIRONMENT', 'test')
        }
        
        # Check for required variables
        missing_vars = [k for k, v in required_env_vars.items() if not v]
        if missing_vars:
            pytest.skip(f"Missing required environment variables: {missing_vars}")
        
        # Set environment variables for the lambda function
        for key, value in required_env_vars.items():
            os.environ[key] = value
        
        yield
        
        # Cleanup (optional)
        pass
    
    @pytest.fixture
    def real_lambda_context(self):
        """Create a mock lambda context for testing"""
        context = Mock()
        context.function_name = "iam-analyzer-integration-test"
        context.aws_request_id = f"test-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        context.get_remaining_time_in_millis.return_value = 300000  # 5 minutes
        context.log_group_name = "/aws/lambda/test"
        context.log_stream_name = f"test-stream-{datetime.now().strftime('%Y%m%d')}"
        return context
    
    @pytest.fixture
    def test_config(self):
        """Test configuration from environment"""
        return {
            'analyzer_arn': os.getenv('ANALYZER_ARN'),
            's3_bucket': os.getenv('S3_BUCKET'),
            's3_prefix': os.getenv('S3_PREFIX'),
            'github_repo': os.getenv('GITHUB_REPO'),
            'github_token': os.getenv('GITHUB_TOKEN'),
            'aws_region': os.getenv('AWS_REGION', 'us-east-1'),
            'resource_filter': os.getenv('TEST_RESOURCE_FILTER', '').split(',') if os.getenv('TEST_RESOURCE_FILTER') else [],
            'create_real_pr': os.getenv('CREATE_REAL_PR', 'false').lower() == 'true',
            'dry_run': os.getenv('DRY_RUN', 'true').lower() == 'true',
            'base_branch': os.getenv('BASE_BRANCH', 'main'),
            'head_branch_prefix': os.getenv('HEAD_BRANCH_PREFIX', 'iam-policy-test')
        }

    def test_aws_connectivity(self, test_config):
        """Test that we can connect to AWS services"""
        print("\n" + "="*80)
        print("Testing AWS Connectivity")
        print("="*80)
        
        try:
            # Test IAM Access Analyzer connection
            analyzer = IAMAnalyzer(region=test_config['aws_region'])
            analyzers = analyzer.list_analyzers()
            print(f"✅ Connected to Access Analyzer. Found {len(analyzers)} analyzers:")
            for i, az in enumerate(analyzers, 1):
                print(f"   {i}. {az.get('name')} ({az.get('status')}) - {az.get('arn')}")
            
            # Verify our target analyzer exists
            target_analyzer = None
            for az in analyzers:
                if az.get('arn') == test_config['analyzer_arn']:
                    target_analyzer = az
                    break
            
            if target_analyzer:
                print(f"✅ Target analyzer found: {target_analyzer.get('name')}")
            else:
                pytest.fail(f"Target analyzer not found: {test_config['analyzer_arn']}")
            
            # Test S3 connection
            s3_client = boto3.client('s3', region_name=test_config['aws_region'])
            response = s3_client.head_bucket(Bucket=test_config['s3_bucket'])
            print(f"✅ Connected to S3 bucket: {test_config['s3_bucket']}")
            
            # Check if resources file exists
            try:
                s3_client.head_object(
                    Bucket=test_config['s3_bucket'],
                    Key=f"{test_config['s3_prefix']}/latest.json"
                )
                print(f"✅ Resources file exists: {test_config['s3_prefix']}/latest.json")
            except s3_client.exceptions.NoSuchKey:
                print(f"⚠️  Resources file not found: {test_config['s3_prefix']}/latest.json")
                print("   This test may fail if no resources are available")
            
        except Exception as e:
            pytest.fail(f"AWS connectivity test failed: {str(e)}")

    def test_fetch_real_resources(self, test_config):
        """Test fetching real IAM resources from S3"""
        print("\n" + "="*80)
        print("Testing Real Resource Fetching")
        print("="*80)
        
        try:
            analyzer = IAMAnalyzer(region=test_config['aws_region'])
            resources = analyzer.fetch_resources_from_s3(
                bucket_name=test_config['s3_bucket'],
                prefix=test_config['s3_prefix']
            )
            
            print(f"✅ Fetched {len(resources)} IAM resources from S3")
            
            # Group resources by type
            resource_types = {}
            for resource in resources:
                resource_type = resource.resource_type.value
                if resource_type not in resource_types:
                    resource_types[resource_type] = []
                resource_types[resource_type].append(resource)
            
            print("\nResource breakdown:")
            for resource_type, type_resources in resource_types.items():
                print(f"  {resource_type}: {len(type_resources)} resources")
                for resource in type_resources[:3]:  # Show first 3 of each type
                    print(f"    - {resource.name} ({resource.arn})")
                if len(type_resources) > 3:
                    print(f"    ... and {len(type_resources) - 3} more")
            
            # Filter resources if specified
            if test_config['resource_filter']:
                filtered_resources = [
                    r for r in resources 
                    if any(filter_name in r.name for filter_name in test_config['resource_filter'])
                ]
                print(f"\n🔍 Filtered to {len(filtered_resources)} resources matching filter: {test_config['resource_filter']}")
                return filtered_resources
            
            return resources
            
        except Exception as e:
            pytest.fail(f"Resource fetching failed: {str(e)}")

    def test_fetch_real_findings(self, test_config):
        """Test fetching real Access Analyzer findings"""
        print("\n" + "="*80)
        print("Testing Real Access Analyzer Findings")
        print("="*80)
        
        try:
            analyzer = IAMAnalyzer(region=test_config['aws_region'])
            
            # First get resources
            resources = analyzer.fetch_resources_from_s3(
                bucket_name=test_config['s3_bucket'],
                prefix=test_config['s3_prefix']
            )
            
            # Filter resources if specified
            if test_config['resource_filter']:
                resources = [
                    r for r in resources 
                    if any(filter_name in r.name for filter_name in test_config['resource_filter'])
                ]
            
            if not resources:
                print("⚠️  No resources available for analysis")
                return [], {}
            
            # Get findings for these resources
            findings, summary = analyzer.list_findings_for_resources(
                analyzer_arn=test_config['analyzer_arn'],
                resources=resources
            )
            
            print(f"✅ Found {len(findings)} Access Analyzer findings")
            print(f"   Summary: {summary.total_findings} total findings")
            print(f"   By type: {summary.findings_by_type}")
            print(f"   By status: {summary.findings_by_status}")
            
            # Show detailed findings
            print("\nDetailed findings:")
            for i, finding in enumerate(findings[:5], 1):  # Show first 5
                resource_arn = finding.get('resource', {}).get('arn') if isinstance(finding.get('resource'), dict) else finding.get('resource', 'unknown')
                print(f"  {i}. {finding.get('findingType')} - {finding.get('status')}")
                print(f"     Resource: {resource_arn}")
                print(f"     ID: {finding.get('id')}")
                print(f"     Created: {finding.get('createdAt', 'unknown')}")
            
            if len(findings) > 5:
                print(f"     ... and {len(findings) - 5} more findings")
            
            return findings, summary
            
        except Exception as e:
            pytest.fail(f"Findings fetching failed: {str(e)}")

    def test_complete_lambda_workflow_dry_run(self, test_config, real_lambda_context):
        """Test the complete lambda workflow in dry-run mode"""
        print("\n" + "="*80)
        print("Testing Complete Lambda Workflow (DRY RUN)")
        print("="*80)
        
        # Mock GitHub operations if dry run is enabled
        original_create_pr = None
        if test_config['dry_run'] or not test_config['create_real_pr']:
            print("🔒 Running in DRY RUN mode - no real GitHub changes will be made")
            
            def mock_create_pull_request(self, title, body, base_branch='main', head_branch='iam-policy-updates', policy_changes=None):
                print(f"\n📝 MOCK PR Creation:")
                print(f"   Title: {title}")
                print(f"   Branch: {head_branch} -> {base_branch}")
                print(f"   Files: {len(policy_changes) if policy_changes else 0}")
                
                if policy_changes:
                    print("\n📁 Files that would be created/updated:")
                    for file_path, content in policy_changes.items():
                        print(f"\n--- {file_path} ---")
                        if isinstance(content, str):
                            # Truncate long content
                            display_content = content[:1000] + "\n..." if len(content) > 1000 else content
                            print(display_content)
                        else:
                            print(json.dumps(content, indent=2)[:1000])
                            if len(json.dumps(content, indent=2)) > 1000:
                                print("...")
                
                return {
                    "status": "success",
                    "pr_number": 999,
                    "pr_url": f"https://github.com/{test_config['github_repo']}/pull/999",
                    "files_committed": len(policy_changes) if policy_changes else 0,
                    "action": "created"
                }
            
            # Patch the GitHub PR handler
            original_create_pr = GitHubPRHandler.create_pull_request
            GitHubPRHandler.create_pull_request = mock_create_pull_request
        
        try:
            # Mock SSM parameter store for GitHub token
            with patch('index.get_github_token') as mock_get_token:
                mock_get_token.return_value = test_config['github_token'] or 'mock-token'
                
                # Create lambda event
                lambda_event = {
                    "test_mode": True,
                    "dry_run": test_config['dry_run']
                }
                
                print(f"🚀 Executing lambda handler...")
                print(f"   Environment: {os.getenv('ENVIRONMENT')}")
                print(f"   Analyzer ARN: {test_config['analyzer_arn']}")
                print(f"   S3 Bucket: {test_config['s3_bucket']}")
                print(f"   S3 Prefix: {test_config['s3_prefix']}")
                print(f"   GitHub Repo: {test_config['github_repo']}")
                
                # Execute the lambda handler
                result = lambda_handler(lambda_event, real_lambda_context)
                
                print(f"\n✅ Lambda execution completed with status: {result['statusCode']}")
                
                # Parse and display results
                response_body = json.loads(result['body'])
                
                print(f"\n📊 Execution Results:")
                print(f"   Status: {response_body.get('status')}")
                print(f"   Message: {response_body.get('message')}")
                print(f"   Resources Analyzed: {response_body.get('resources_analyzed', 0)}")
                print(f"   Findings Count: {response_body.get('findings_count', 0)}")
                print(f"   Detailed Findings: {response_body.get('detailed_findings_count', 0)}")
                print(f"   Recommendations: {response_body.get('recommendations_count', 0)}")
                print(f"   PR Created: {response_body.get('pr_created', False)}")
                
                if 'finding_summary' in response_body:
                    print(f"\n📈 Finding Summary:")
                    summary = response_body['finding_summary']
                    print(f"   By Type: {summary.get('by_type', {})}")
                    print(f"   By Status: {summary.get('by_status', {})}")
                
                if response_body.get('unused_services_found'):
                    print(f"   Unused Services Found: {response_body['unused_services_found']}")
                    print(f"   Total Unused Actions: {response_body['total_unused_actions']}")
                
                # Assert success
                assert result['statusCode'] == 200, f"Lambda failed with: {response_body}"
                
                return result
                
        finally:
            # Restore original GitHub method if we mocked it
            if original_create_pr:
                GitHubPRHandler.create_pull_request = original_create_pr

    @pytest.mark.live_pr
    def test_create_real_github_pr(self, test_config, real_lambda_context):
        """Test creating a real GitHub PR (only runs with --live-pr flag)"""
        if not test_config['create_real_pr']:
            pytest.skip("Skipping real PR creation (set CREATE_REAL_PR=true to enable)")
        
        if not test_config['github_token']:
            pytest.skip("No GitHub token provided")
        
        print("\n" + "="*80)
        print("Testing REAL GitHub PR Creation")
        print("="*80)
        print("⚠️  This will create a REAL pull request in your repository!")
        
        # Add timestamp to branch name to avoid conflicts
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        head_branch = f"{test_config['head_branch_prefix']}-{timestamp}"
        
        # Mock SSM parameter store for GitHub token
        with patch('index.get_github_token') as mock_get_token:
            mock_get_token.return_value = test_config['github_token']
            
            # Temporarily disable dry run
            original_dry_run = os.getenv('DRY_RUN')
            os.environ['DRY_RUN'] = 'false'
            
            try:
                # Create lambda event
                lambda_event = {
                    "test_mode": True,
                    "dry_run": False,
                    "head_branch": head_branch
                }
                
                print(f"🚀 Creating real PR with branch: {head_branch}")
                
                # Execute the lambda handler
                result = lambda_handler(lambda_event, real_lambda_context)
                
                # Parse results
                response_body = json.loads(result['body'])
                
                print(f"\n✅ Real PR test completed:")
                print(f"   Status: {result['statusCode']}")
                print(f"   PR Created: {response_body.get('pr_created', False)}")
                
                if response_body.get('pr_created'):
                    print(f"   🔗 PR URL: Check your GitHub repository for the new PR")
                    print(f"   📝 Branch: {head_branch}")
                    print(f"   📊 Recommendations: {response_body.get('recommendations_count', 0)}")
                
                return result
                
            finally:
                # Restore original dry run setting
                if original_dry_run:
                    os.environ['DRY_RUN'] = original_dry_run

    def test_policy_recommender_output_format(self, test_config):
        """Test the policy recommender output format to show what would be in PRs"""
        print("\n" + "="*80)
        print("Testing Policy Recommender Output Format")
        print("="*80)
        
        try:
            # Initialize components
            analyzer = IAMAnalyzer(region=test_config['aws_region'])
            
            # Mock GitHub and AWS services for PolicyRecommender
            with patch('modules.policy_recommender.Github') as mock_github_class, \
                 patch('modules.policy_recommender.boto3') as mock_boto3:
                
                # Mock GitHub
                mock_github = Mock()
                mock_repo = Mock()
                mock_github.get_repo.return_value = mock_repo
                mock_github_class.return_value = mock_github
                
                # Mock AWS Access Analyzer for validation
                mock_access_analyzer = Mock()
                mock_access_analyzer.validate_policy.return_value = {
                    'findings': []  # Return valid policy
                }
                mock_boto3.client.return_value = mock_access_analyzer
                
                policy_recommender = PolicyRecommender(
                    github_token=test_config['github_token'] or 'mock-token',
                    repo_name=test_config['github_repo']
                )
            
            # Get resources and findings
            resources = analyzer.fetch_resources_from_s3(
                bucket_name=test_config['s3_bucket'],
                prefix=test_config['s3_prefix']
            )
            
            # Filter resources if specified
            if test_config['resource_filter']:
                resources = [
                    r for r in resources 
                    if any(filter_name in r.name for filter_name in test_config['resource_filter'])
                ]
            
            if not resources:
                print("⚠️  No resources available for policy recommendation testing")
                return
            
            findings, summary = analyzer.list_findings_for_resources(
                analyzer_arn=test_config['analyzer_arn'],
                resources=resources
            )
            
            if not findings:
                print("⚠️  No findings available for policy recommendation testing")
                return
            
            # Convert resources to dict format
            resources_dict = []
            for resource in resources:
                resources_dict.append({
                    "ResourceARN": resource.arn,
                    "ResourceType": resource.resource_type.value,
                    "ResourceName": resource.name,
                    "tf_resource_name": resource.name.replace('-', '_')
                })
            
            # Fetch detailed findings
            detailed_findings = policy_recommender.fetch_detailed_findings(
                test_config['analyzer_arn'], 
                findings
            )
            
            print(f"📋 Processing {len(detailed_findings)} detailed findings...")
            
            # Process findings to get recommendations
            recommendations = policy_recommender.process_detailed_findings(
                detailed_findings, 
                resources_dict
            )
            
            if not recommendations:
                print("ℹ️  No policy recommendations generated")
                return
            
            print(f"\n📝 Generated {len(recommendations)} policy recommendations:")
            
            # Show what would be in the PR
            for resource_key, recommendation in recommendations.items():
                print(f"\n🔍 Resource: {resource_key}")
                print(f"   Finding ID: {recommendation.get('finding_id')}")
                print(f"   Resource Type: {recommendation.get('resource_type')}")
                print(f"   Recommendation Type: {recommendation.get('recommendation_type')}")
                print(f"   Confidence: {recommendation.get('confidence')}")
                print(f"   Action Required: {recommendation.get('action_required')}")
                
                if 'unused_services' in recommendation:
                    unused_services = recommendation['unused_services']
                    print(f"   Unused Services ({len(unused_services)}): {', '.join(unused_services)}")
                
                if 'unused_actions' in recommendation:
                    unused_count = len(recommendation['unused_actions'])
                    print(f"   Unused Actions: {unused_count}")
                    if unused_count <= 5:
                        for action in recommendation['unused_actions']:
                            print(f"     - {action}")
                    else:
                        for action in recommendation['unused_actions'][:3]:
                            print(f"     - {action}")
                        print(f"     ... and {unused_count - 3} more")
                
                print(f"   Recommendation Reason: {recommendation.get('recommendation_reason', 'N/A')}")
            
            # Test the PR creation process with mock
            print(f"\n📁 Testing PR creation process...")
            
            # Mock the GitHub PR creation methods
            mock_files_created = {}
            
            def mock_create_github_pr(title, body, files):
                """Mock GitHub PR creation to capture what would be created"""
                print(f"\n📝 Mock PR Creation:")
                print(f"   Title: {title}")
                print(f"   Files to be created/updated: {len(files)}")
                
                for file_info in files:
                    file_path = file_info['path']
                    content = file_info['content']
                    mock_files_created[file_path] = content
                    
                    print(f"\n--- {file_path} ---")
                    # Show first 500 characters of content
                    if isinstance(content, str):
                        display_content = content[:500]
                        if len(content) > 500:
                            display_content += "\n... (truncated)"
                        print(display_content)
                    else:
                        print(json.dumps(content, indent=2)[:500])
                
                return True
            
            # Patch the _create_github_pr method
            policy_recommender._create_github_pr = mock_create_github_pr
            
            # Mock the _download_terraform_files method to return empty dict
            policy_recommender._download_terraform_files = lambda: {}
            
            # Test PR creation
            success = policy_recommender.create_policy_updates_pr(recommendations)
            
            print(f"\n✅ PR creation test {'succeeded' if success else 'failed'}")
            print(f"📊 Total files that would be created: {len(mock_files_created)}")
            
            # Show summary of what would be in the PR
            if mock_files_created:
                print("\n📋 Summary of files that would be created:")
                for file_path in mock_files_created.keys():
                    print(f"   - {file_path}")
            
            # Test the AWS validation is working
            print(f"\n🔍 Testing AWS policy validation...")
            sample_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "*"
                    }
                ]
            }
            
            validation_result = policy_recommender._validate_policy_with_aws(
                sample_policy, 
                "test_policy"
            )
            
            print(f"   Validation Result: {'✅ Valid' if validation_result['is_valid'] else '❌ Invalid'}")
            if not validation_result['is_valid']:
                print(f"   Errors: {validation_result['errors']}")
            if validation_result['warning_count'] > 0:
                print(f"   Warnings: {validation_result['warnings']}")
            
        except Exception as e:
            print(f"❌ Policy recommender test failed: {str(e)}")
            import traceback
            traceback.print_exc()
            raise

    def test_environment_validation(self):
        """Test environment validation"""
        print("\n" + "="*80)
        print("Testing Environment Validation")
        print("="*80)
        
        try:
            validate_environment()
            print("✅ Environment validation passed")
        except ValueError as e:
            pytest.fail(f"Environment validation failed: {str(e)}")

if __name__ == "__main__":
    # Run tests with verbose output and show print statements
    import subprocess
    
    print("Running Real AWS Integration Tests...")
    print("Make sure you have configured your .env file with real AWS credentials!")
    
    # Run pytest with appropriate flags
    cmd = [
        "python3", "-m", "pytest", 
        __file__, 
        "-v", "-s",  # verbose and show prints
        "--tb=short",  # shorter traceback
        "-x"  # stop on first failure
    ]
    
    # Add live PR test if requested
    if os.getenv('CREATE_REAL_PR', 'false').lower() == 'true':
        cmd.extend(["-m", "live_pr"])
        print("Including live PR creation tests...")
    
    subprocess.run(cmd)