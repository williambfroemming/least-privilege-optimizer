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

    @patch.dict(os.environ, {
        'GITHUB_REPO': 'test/repo',
        'ANALYZER_ARN': 'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
        'S3_BUCKET': 'test-bucket',
        'S3_PREFIX': 'test-prefix',
        'AWS_REGION': 'us-east-1',
        'GITHUB_BRANCH': 'demo'
    })
    @patch('src.index.get_github_token')
    @patch('src.index.PolicyRecommender')
    @patch('src.index.IAMAnalyzer')
    def test_complete_workflow_success(self, mock_analyzer_class, mock_policy_class, mock_github_token):
        """Test the complete workflow from S3 fetch to PR creation"""
        # Mock the github token
        mock_github_token.return_value = 'fake-token'
        
        # Mock the analyzer instance and methods
        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        
        # Mock successful resource analysis
        mock_resources = [
            MagicMock(arn='arn:aws:iam::123456789012:user/test-user-1', name='test-user-1', resource_type=MagicMock(value='AWS::IAM::User'))
        ]
        mock_findings = [{'id': 'finding-1', 'findingType': 'UNUSED_ACCESS'}]
        mock_summary = MagicMock(total_findings=1, findings_by_type={'UNUSED_ACCESS': 1}, findings_by_status={'ACTIVE': 1})
        
        mock_analyzer.analyze_resources_from_s3.return_value = (mock_resources, mock_findings, mock_summary)
        
        # Mock the policy recommender instance and methods  
        mock_recommender = MagicMock()
        mock_policy_class.return_value = mock_recommender
        
        # Mock detailed findings and recommendations
        mock_detailed_findings = {'finding-1': {'basic_finding': {'id': 'finding-1'}, 'unused_services': ['ecr']}}
        mock_recommendations = {'test_resource': {'unused_services': ['ecr'], 'unused_actions': ['ecr:*']}}
        
        mock_recommender.fetch_detailed_findings.return_value = mock_detailed_findings
        mock_recommender.process_detailed_findings.return_value = mock_recommendations
        mock_recommender.create_policy_updates_pr.return_value = True
        
        # Call the lambda handler
        from src.index import lambda_handler
        result = lambda_handler({}, MagicMock())
        
        # Verify the result
        assert result['statusCode'] == 200
        response_body = json.loads(result['body'])
        assert response_body['status'] == 'success'
        assert response_body['pr_created'] is True
        assert response_body['recommendations_count'] == 1
        
        # Verify that the policy recommender was initialized with the demo branch
        mock_policy_class.assert_called_once()
        call_args = mock_policy_class.call_args
        assert call_args[1]['branch'] == 'demo'

    @patch.dict(os.environ, {
        'GITHUB_REPO': 'test/repo',
        'ANALYZER_ARN': 'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
        'S3_BUCKET': 'test-bucket',
        'S3_PREFIX': 'test-prefix',
        'AWS_REGION': 'us-east-1',
        'GITHUB_BRANCH': 'demo'
    })
    @patch('src.index.get_github_token')
    @patch('src.index.PolicyRecommender')
    @patch('src.index.IAMAnalyzer')
    def test_s3_fetch_failure(self, mock_analyzer_class, mock_policy_class, mock_github_token):
        """Test handling of S3 fetch failures"""
        # Mock the github token
        mock_github_token.return_value = 'fake-token'
        
        # Mock the analyzer instance
        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        
        # Mock S3 failure
        from botocore.exceptions import ClientError
        error_response = {'Error': {'Code': 'NoSuchBucket', 'Message': 'Bucket not found'}}
        mock_analyzer.analyze_resources_from_s3.side_effect = ClientError(error_response, 'GetObject')
        
        # Mock the policy recommender (won't be reached due to S3 failure)
        mock_recommender = MagicMock()
        mock_policy_class.return_value = mock_recommender
        
        # Call the lambda handler
        from src.index import lambda_handler
        result = lambda_handler({}, MagicMock())
        
        # Verify error response
        assert result['statusCode'] == 500
        response_body = json.loads(result['body'])
        assert response_body['status'] == 'failed'
        assert 'error' in response_body

    @patch.dict(os.environ, {
        'GITHUB_REPO': 'test/repo',
        'ANALYZER_ARN': 'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
        'S3_BUCKET': 'test-bucket',
        'S3_PREFIX': 'test-prefix',
        'AWS_REGION': 'us-east-1',
        'GITHUB_BRANCH': 'demo'
    })
    @patch('src.index.get_github_token')
    @patch('src.index.PolicyRecommender')
    @patch('src.index.IAMAnalyzer')
    def test_access_analyzer_failure(self, mock_analyzer_class, mock_policy_class, mock_github_token):
        """Test handling of Access Analyzer API failures"""
        # Mock the github token
        mock_github_token.return_value = 'fake-token'
        
        # Mock the analyzer instance
        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        
        # Mock Access Analyzer failure
        from botocore.exceptions import ClientError
        error_response = {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}}
        mock_analyzer.analyze_resources_from_s3.side_effect = ClientError(error_response, 'ListFindingsV2')
        
        # Mock the policy recommender (won't be reached due to Access Analyzer failure)
        mock_recommender = MagicMock()
        mock_policy_class.return_value = mock_recommender
        
        # Call the lambda handler
        from src.index import lambda_handler
        result = lambda_handler({}, MagicMock())
        
        # Verify error response
        assert result['statusCode'] == 500
        response_body = json.loads(result['body'])
        assert response_body['status'] == 'failed'
        assert 'error' in response_body

    @patch.dict(os.environ, {
        'GITHUB_REPO': 'test/repo',
        'ANALYZER_ARN': 'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
        'S3_BUCKET': 'test-bucket',
        'S3_PREFIX': 'test-prefix',
        'AWS_REGION': 'us-east-1',
        'GITHUB_BRANCH': 'demo'
    })
    @patch('src.index.get_github_token')
    @patch('src.index.PolicyRecommender')
    @patch('src.index.IAMAnalyzer')
    def test_github_pr_failure(self, mock_analyzer_class, mock_policy_class, mock_github_token):
        """Test handling of GitHub PR creation failures"""
        # Mock the github token
        mock_github_token.return_value = 'fake-token'
        
        # Mock the analyzer instance with successful analysis
        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        
        mock_resources = [
            MagicMock(arn='arn:aws:iam::123456789012:user/test-user-1', name='test-user-1', resource_type=MagicMock(value='AWS::IAM::User'))
        ]
        mock_findings = [{'id': 'finding-1', 'findingType': 'UNUSED_ACCESS'}]
        mock_summary = MagicMock(total_findings=1, findings_by_type={'UNUSED_ACCESS': 1}, findings_by_status={'ACTIVE': 1})
        
        mock_analyzer.analyze_resources_from_s3.return_value = (mock_resources, mock_findings, mock_summary)
        
        # Mock the policy recommender with PR failure
        mock_recommender = MagicMock()
        mock_policy_class.return_value = mock_recommender
        
        mock_detailed_findings = {'finding-1': {'basic_finding': {'id': 'finding-1'}, 'unused_services': ['ecr']}}
        mock_recommendations = {'test_resource': {'unused_services': ['ecr'], 'unused_actions': ['ecr:*']}}
        
        mock_recommender.fetch_detailed_findings.return_value = mock_detailed_findings
        mock_recommender.process_detailed_findings.return_value = mock_recommendations
        mock_recommender.create_policy_updates_pr.return_value = False  # PR creation fails
        
        # Call the lambda handler
        from src.index import lambda_handler
        result = lambda_handler({}, MagicMock())
        
        # Verify the result - should still be 200 but with pr_created = False
        assert result['statusCode'] == 200
        response_body = json.loads(result['body'])
        assert response_body['status'] == 'partial_success'
        assert response_body['pr_created'] is False
        assert response_body['recommendations_count'] == 1

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
            from src.index import lambda_handler
            result = lambda_handler(incomplete_event, lambda_context)
            
            assert result['statusCode'] == 500  # Environment validation fails with 500
            response_body = json.loads(result['body'])
            assert response_body['status'] == 'failed'
            assert 'Missing required environment variables' in response_body['error']

    @patch.dict(os.environ, {
        'GITHUB_REPO': 'test/repo',
        'ANALYZER_ARN': 'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
        'S3_BUCKET': 'test-bucket',
        'S3_PREFIX': 'test-prefix',
        'AWS_REGION': 'us-east-1',
        'GITHUB_BRANCH': 'demo'
    })
    @patch('src.index.get_github_token')
    @patch('src.index.PolicyRecommender')
    @patch('src.index.IAMAnalyzer')
    def test_edge_cases_handling(self, mock_analyzer_class, mock_policy_class, mock_github_token):
        """Test handling of various edge cases in findings data"""
        # Mock the github token
        mock_github_token.return_value = 'fake-token'
        
        # Mock the analyzer instance
        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        
        # Mock edge case: some resources but no findings
        mock_resources = [
            MagicMock(arn='arn:aws:iam::123456789012:user/valid-user', name='valid-user', resource_type=MagicMock(value='AWS::IAM::User'))
        ]
        mock_findings = []  # No findings for edge case testing
        mock_summary = MagicMock(total_findings=0, findings_by_type={}, findings_by_status={})
        
        mock_analyzer.analyze_resources_from_s3.return_value = (mock_resources, mock_findings, mock_summary)
        
        # Mock the policy recommender
        mock_recommender = MagicMock()
        mock_policy_class.return_value = mock_recommender
        
        # Should not be called due to no findings
        mock_recommender.fetch_detailed_findings.return_value = {}
        mock_recommender.process_detailed_findings.return_value = {}
        
        # Call the lambda handler
        from src.index import lambda_handler
        result = lambda_handler({}, MagicMock())
        
        # Should handle edge case gracefully - no findings should result in success message
        assert result['statusCode'] == 200
        response_body = json.loads(result['body'])
        assert response_body['status'] == 'success'
        assert response_body['findings_count'] == 0
        assert 'No findings to analyze' in response_body['message']


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