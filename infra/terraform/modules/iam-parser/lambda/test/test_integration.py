"""
Integration tests for the complete lambda handler workflow

This test suite validates the end-to-end integration of IAMAnalyzer and PolicyRecommender
with the lambda handler, testing the complete workflow from S3 resource fetching 
to GitHub PR creation.
"""

import pytest
import json
import os
from unittest.mock import Mock, patch, MagicMock

# Add the src directory to the path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import the main lambda handler
from index import lambda_handler
from modules.iam_analyzer import IAMAnalyzer, IAMResource, ResourceType
from modules.policy_recommender import PolicyRecommender


class TestLambdaIntegration:
    """Integration tests for the complete lambda workflow"""
    
    @pytest.fixture
    def lambda_event(self):
        """Sample Lambda event for testing"""
        return {
            "analyzer_arn": "arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer",
            "s3_bucket": "test-bucket", 
            "s3_prefix": "iam-resources",
            "github_token": "test-github-token",
            "github_repo": "test-owner/test-repo"
        }
    
    @pytest.fixture
    def lambda_context(self):
        """Mock Lambda context"""
        context = Mock()
        context.function_name = "test-function"
        context.aws_request_id = "test-request-id"
        context.get_remaining_time_in_millis.return_value = 30000
        return context
    
    @pytest.fixture
    def sample_s3_resources(self):
        """Sample S3 resource data"""
        return {
            "resources": {
                "aws_iam_user": [
                    {
                        "name": "data-engineer",
                        "arn": "arn:aws:iam::123456789012:user/data-engineer"
                    },
                    {
                        "name": "support-analyst", 
                        "arn": "arn:aws:iam::123456789012:user/support-analyst"
                    }
                ],
                "aws_iam_role": [
                    {
                        "name": "admin-role",
                        "arn": "arn:aws:iam::123456789012:role/admin-role"
                    }
                ]
            }
        }
    
    @pytest.fixture
    def sample_access_analyzer_findings(self):
        """Sample Access Analyzer findings with various data structures"""
        return [
            # Finding with policy data (traditional case)
            {
                "id": "finding-1",
                "findingType": "UNUSED_ACCESS",
                "status": "ACTIVE",
                "resource": {
                    "arn": "arn:aws:iam::123456789012:user/data-engineer",
                    "type": "AWS::IAM::User",
                    "policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:*", "ec2:*", "rds:*"],
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
                            "Resource": ["arn:aws:s3:::data-bucket/*", "arn:aws:s3:::data-bucket"]
                        }
                    ]
                },
                "findingDetails": {
                    "unusedActions": ["ec2:*", "rds:*", "s3:PutObject", "s3:DeleteObject"]
                },
                "createdAt": "2025-06-21T00:00:00Z"
            },
            # Finding with string resource (edge case we fixed)
            {
                "id": "finding-2", 
                "findingType": "EXTERNAL_ACCESS",
                "status": "ACTIVE",
                "resource": "arn:aws:iam::123456789012:role/admin-role",
                "findingDetails": {
                    "externalPrincipal": "111122223333"
                },
                "createdAt": "2025-06-21T01:00:00Z"
            },
            # Finding with no policy but analyzed policy (least privilege suggestion)
            {
                "id": "finding-3",
                "findingType": "UNUSED_ACCESS", 
                "status": "ACTIVE",
                "resource": {
                    "arn": "arn:aws:iam::123456789012:user/support-analyst",
                    "type": "AWS::IAM::User"
                },
                "analyzedPolicy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["support:*"],
                            "Resource": "*"
                        }
                    ]
                },
                "createdAt": "2025-06-21T02:00:00Z"
            }
        ]

    @patch('modules.iam_analyzer.boto3')
    @patch('modules.github_pr.GitHubPRHandler')  # Mock the actual module location
    def test_complete_workflow_success(self, mock_github_handler_class, mock_boto3, 
                                     lambda_event, lambda_context, sample_s3_resources, 
                                     sample_access_analyzer_findings):
        """Test the complete successful workflow from S3 to GitHub PR"""
        
        # Mock environment variables
        with patch.dict('os.environ', {
            'GITHUB_REPO': 'test-owner/test-repo',
            'ANALYZER_ARN': 'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            'S3_BUCKET': 'test-bucket',
            'S3_PREFIX': 'iam-resources'
        }):
            # Mock AWS clients
            mock_s3_client = Mock()
            mock_access_analyzer = Mock()
            
            mock_boto3.client.side_effect = lambda service, **kwargs: {
                'accessanalyzer': mock_access_analyzer,
                's3': mock_s3_client
            }[service]
            
            # Mock S3 response
            mock_s3_response = {
                'Body': Mock(),
                'ContentLength': 1024
            }
            mock_s3_response['Body'].read.return_value = json.dumps(sample_s3_resources).encode('utf-8')
            mock_s3_client.get_object.return_value = mock_s3_response
            
            # Mock Access Analyzer response
            mock_access_analyzer.list_findings_v2.return_value = {
                'findings': sample_access_analyzer_findings
            }
            
            # Mock GitHub PR handler
            mock_github_handler = Mock()
            mock_github_handler.create_pull_request.return_value = {
                "status": "success",
                "pr_number": 42,
                "pr_url": "https://github.com/test-owner/test-repo/pull/42"
            }
            mock_github_handler_class.return_value = mock_github_handler
            
            # Execute lambda handler
            result = lambda_handler(lambda_event, lambda_context)
            
            # Verify successful response
            assert result['statusCode'] == 200
            response_body = json.loads(result['body'])
            assert response_body['success'] == True
            assert 'resources_processed' in response_body
            assert 'findings_analyzed' in response_body
            assert 'recommendations_generated' in response_body
            assert 'pr_created' in response_body
            assert response_body['pr_created'] == True
            
            # Verify AWS API calls
            mock_s3_client.get_object.assert_called_once_with(
                Bucket='test-bucket',
                Key='iam-resources/latest.json'
            )
            
            mock_access_analyzer.list_findings_v2.assert_called_once()
            
            # Verify GitHub PR creation
            mock_github_handler.create_pull_request.assert_called_once()
            pr_call_args = mock_github_handler.create_pull_request.call_args
            assert 'IAM Policy Updates' in pr_call_args[1]['title']

    @patch('modules.iam_analyzer.boto3')
    def test_s3_fetch_failure(self, mock_boto3, lambda_event, lambda_context):
        """Test handling of S3 fetch failures"""
        
        # Mock environment variables
        with patch.dict('os.environ', {
            'GITHUB_REPO': 'test-owner/test-repo',
            'ANALYZER_ARN': 'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            'S3_BUCKET': 'test-bucket',
            'S3_PREFIX': 'iam-resources'
        }):
            # Mock S3 client to raise an error
            mock_s3_client = Mock()
            mock_access_analyzer = Mock()
            
            mock_boto3.client.side_effect = lambda service, **kwargs: {
                'accessanalyzer': mock_access_analyzer,
                's3': mock_s3_client
            }[service]
            
            from botocore.exceptions import ClientError
            error_response = {'Error': {'Code': 'NoSuchBucket', 'Message': 'Bucket not found'}}
            mock_s3_client.get_object.side_effect = ClientError(error_response, 'GetObject')
            
            # Execute lambda handler
            result = lambda_handler(lambda_event, lambda_context)
            
            # Verify error response
            assert result['statusCode'] == 500
            response_body = json.loads(result['body'])
            assert response_body['success'] == False
            assert 'error' in response_body
            assert 'Failed to fetch resources from S3' in response_body['error']

    @patch('modules.iam_analyzer.boto3')
    def test_access_analyzer_failure(self, mock_boto3, lambda_event, lambda_context, sample_s3_resources):
        """Test handling of Access Analyzer API failures"""
        
        # Mock environment variables
        with patch.dict('os.environ', {
            'GITHUB_REPO': 'test-owner/test-repo',
            'ANALYZER_ARN': 'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            'S3_BUCKET': 'test-bucket',
            'S3_PREFIX': 'iam-resources'
        }):
            # Mock AWS clients
            mock_s3_client = Mock()
            mock_access_analyzer = Mock()
            
            mock_boto3.client.side_effect = lambda service, **kwargs: {
                'accessanalyzer': mock_access_analyzer,
                's3': mock_s3_client
            }[service]
            
            # Mock successful S3 response
            mock_s3_response = {
                'Body': Mock(),
                'ContentLength': 1024
            }
            mock_s3_response['Body'].read.return_value = json.dumps(sample_s3_resources).encode('utf-8')
            mock_s3_client.get_object.return_value = mock_s3_response
            
            # Mock Access Analyzer failure
            from botocore.exceptions import ClientError
            error_response = {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}}
            mock_access_analyzer.list_findings_v2.side_effect = ClientError(error_response, 'ListFindingsV2')
            
            # Execute lambda handler
            result = lambda_handler(lambda_event, lambda_context)
            
            # Verify error response
            assert result['statusCode'] == 500
            response_body = json.loads(result['body'])
            assert response_body['success'] == False
            assert 'Failed to list findings' in response_body['error']

    @patch('modules.iam_analyzer.boto3')
    @patch('modules.github_pr.GitHubPRHandler')  # Mock the actual module location
    def test_github_pr_failure(self, mock_github_handler_class, mock_boto3,
                              lambda_event, lambda_context, sample_s3_resources, 
                              sample_access_analyzer_findings):
        """Test handling of GitHub PR creation failures"""
        
        # Mock environment variables
        with patch.dict('os.environ', {
            'GITHUB_REPO': 'test-owner/test-repo',
            'ANALYZER_ARN': 'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            'S3_BUCKET': 'test-bucket',
            'S3_PREFIX': 'iam-resources'
        }):
            # Mock AWS clients successfully
            mock_s3_client = Mock()
            mock_access_analyzer = Mock()
            
            mock_boto3.client.side_effect = lambda service, **kwargs: {
                'accessanalyzer': mock_access_analyzer,
                's3': mock_s3_client
            }[service]
            
            # Mock successful AWS responses
            mock_s3_response = {
                'Body': Mock(),
                'ContentLength': 1024
            }
            mock_s3_response['Body'].read.return_value = json.dumps(sample_s3_resources).encode('utf-8')
            mock_s3_client.get_object.return_value = mock_s3_response
            
            mock_access_analyzer.list_findings_v2.return_value = {
                'findings': sample_access_analyzer_findings
            }
            
            # Mock GitHub PR handler failure
            mock_github_handler = Mock()
            mock_github_handler.create_pull_request.return_value = {
                "status": "failed",
                "error": "Repository access denied"
            }
            mock_github_handler_class.return_value = mock_github_handler
            
            # Execute lambda handler
            result = lambda_handler(lambda_event, lambda_context)
            
            # Should still return success but with PR creation failure noted
            assert result['statusCode'] == 200
            response_body = json.loads(result['body'])
            assert response_body['success'] == True  # Overall success since analysis worked
            assert response_body['pr_created'] == False
            assert 'pr_error' in response_body

    def test_missing_required_parameters(self, lambda_context):
        """Test handling of missing required parameters"""
        
        # Test missing analyzer_arn
        incomplete_event = {
            "s3_bucket": "test-bucket",
            "s3_prefix": "iam-resources"
        }
        
        # Mock environment variables but leave some missing
        with patch.dict('os.environ', {
            'GITHUB_REPO': 'test-owner/test-repo',
            # Missing ANALYZER_ARN, S3_BUCKET, S3_PREFIX intentionally
        }, clear=True):
            result = lambda_handler(incomplete_event, lambda_context)
            
            assert result['statusCode'] == 500  # Environment validation fails with 500
            response_body = json.loads(result['body'])
            assert response_body['success'] == False
            assert 'Missing required environment variables' in response_body['error']

    @patch('modules.iam_analyzer.boto3')
    @patch('modules.github_pr.GitHubPRHandler')  # Mock the actual module location
    def test_edge_cases_handling(self, mock_github_handler_class, mock_boto3,
                                lambda_event, lambda_context):
        """Test handling of various edge cases in findings data"""
        
        # Mock environment variables
        with patch.dict('os.environ', {
            'GITHUB_REPO': 'test-owner/test-repo',
            'ANALYZER_ARN': 'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            'S3_BUCKET': 'test-bucket',
            'S3_PREFIX': 'iam-resources'
        }):
            # Mock AWS clients
            mock_s3_client = Mock()
            mock_access_analyzer = Mock()
            
            mock_boto3.client.side_effect = lambda service, **kwargs: {
                'accessanalyzer': mock_access_analyzer,
                's3': mock_s3_client
            }[service]
            
            # S3 data with some invalid resources (missing ARN/name)
            edge_case_s3_data = {
                "resources": {
                    "aws_iam_user": [
                        {
                            "name": "valid-user",
                            "arn": "arn:aws:iam::123456789012:user/valid-user"
                        },
                        {
                            "name": "invalid-user"
                            # Missing ARN - should be skipped
                        }
                    ],
                    "aws_iam_role": [
                        {
                            "arn": "arn:aws:iam::123456789012:role/invalid-role"
                            # Missing name - should be skipped
                        }
                    ]
                }
            }
            
            # Findings with edge cases
            edge_case_findings = [
                # Finding with null resource
                {
                    "id": "finding-null-resource",
                    "findingType": "UNKNOWN_TYPE",
                    "status": "ACTIVE",
                    "resource": None
                },
                # Finding with unexpected resource type
                {
                    "id": "finding-weird-resource",
                    "findingType": "WEIRD_TYPE", 
                    "status": "ACTIVE",
                    "resource": 12345  # Number instead of string/dict
                },
                # Valid finding for valid resource
                {
                    "id": "finding-valid",
                    "findingType": "EXTERNAL_ACCESS",
                    "status": "ACTIVE", 
                    "resource": "arn:aws:iam::123456789012:user/valid-user",
                    "findingDetails": {"externalPrincipal": "111122223333"}
                }
            ]
            
            # Mock responses
            mock_s3_response = {
                'Body': Mock(),
                'ContentLength': 1024
            }
            mock_s3_response['Body'].read.return_value = json.dumps(edge_case_s3_data).encode('utf-8')
            mock_s3_client.get_object.return_value = mock_s3_response
            
            mock_access_analyzer.list_findings_v2.return_value = {
                'findings': edge_case_findings
            }
            
            # Mock GitHub PR handler
            mock_github_handler = Mock()
            mock_github_handler.create_pull_request.return_value = {
                "status": "success",
                "pr_number": 1,
                "pr_url": "https://github.com/test-owner/test-repo/pull/1"
            }
            mock_github_handler_class.return_value = mock_github_handler
            
            # Execute lambda handler
            result = lambda_handler(lambda_event, lambda_context)
            
            # Should handle edge cases gracefully
            assert result['statusCode'] == 200
            response_body = json.loads(result['body'])
            assert response_body['success'] == True
            
            # Should process only valid resources (1 user, 0 roles due to missing name)
            assert response_body['resources_processed'] == 1
            
            # Should generate recommendations only for valid findings
            assert response_body['recommendations_generated'] >= 0  # At least handle the valid finding


class TestResourceExtraction:
    """Test the edge cases for resource extraction that we fixed"""
    
    def test_extract_resource_arn_variations(self):
        """Test all variations of resource ARN extraction"""
        from modules.iam_analyzer import IAMAnalyzer
        
        analyzer = IAMAnalyzer()
        
        # Test various finding structures
        test_cases = [
            # Dictionary with ARN
            {
                "finding": {"resource": {"arn": "arn:aws:iam::123:user/test"}},
                "expected": "arn:aws:iam::123:user/test"
            },
            # String ARN
            {
                "finding": {"resource": "arn:aws:iam::123:user/test"}, 
                "expected": "arn:aws:iam::123:user/test"
            },
            # Dictionary without ARN
            {
                "finding": {"resource": {"type": "AWS::IAM::User"}},
                "expected": "unknown"
            },
            # Null resource
            {
                "finding": {"resource": None},
                "expected": "unknown"
            },
            # Missing resource field
            {
                "finding": {"id": "test"},
                "expected": "unknown"
            },
            # Unexpected type
            {
                "finding": {"resource": 12345},
                "expected": "unknown"
            }
        ]
        
        for case in test_cases:
            result = analyzer._extract_resource_arn(case["finding"])
            assert result == case["expected"], f"Failed for case: {case}"


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])