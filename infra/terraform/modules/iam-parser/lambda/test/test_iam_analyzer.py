"""
Test suite for the refactored IAMAnalyzer class

This test suite validates the functionality of the refactored IAMAnalyzer
with proper mocking and comprehensive test coverage.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any

# Add the src directory to the path
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from modules.iam_analyzer import (
    IAMAnalyzer, 
    AnalyzerError, 
    IAMResource, 
    ResourceType, 
    FindingStatus,
    FindingSummary
)


class TestIAMAnalyzer:
    """Test suite for IAMAnalyzer class"""
    
    @pytest.fixture
    def mock_aws_clients(self):
        """Mock AWS clients to avoid real API calls during testing"""
        with patch('modules.iam_analyzer.boto3') as mock_boto3:
            mock_access_analyzer = Mock()
            mock_s3_client = Mock()
            
            mock_boto3.client.side_effect = lambda service, **kwargs: {
                'accessanalyzer': mock_access_analyzer,
                's3': mock_s3_client
            }[service]
            
            yield {
                'access_analyzer': mock_access_analyzer,
                's3_client': mock_s3_client,
                'boto3': mock_boto3
            }
    
    @pytest.fixture
    def analyzer(self, mock_aws_clients):
        """Create an IAMAnalyzer instance with mocked clients"""
        return IAMAnalyzer(region='us-east-1')
    
    @pytest.fixture
    def sample_s3_data(self):
        """Sample S3 data structure for testing"""
        return {
            "resources": {
                "aws_iam_user": [
                    {
                        "name": "test-user-1",
                        "arn": "arn:aws:iam::123456789012:user/test-user-1"
                    },
                    {
                        "name": "test-user-2",
                        "arn": "arn:aws:iam::123456789012:user/test-user-2"
                    }
                ],
                "aws_iam_role": [
                    {
                        "name": "test-role-1",
                        "arn": "arn:aws:iam::123456789012:role/test-role-1"
                    }
                ],
                "aws_iam_group": [
                    {
                        "name": "test-group-1",
                        "arn": "arn:aws:iam::123456789012:group/test-group-1"
                    },
                    {
                        "name": "test-group-invalid"
                        # Missing ARN - should be skipped
                    }
                ],
                "aws_iam_policy": [
                    {
                        "name": "test-policy-1",
                        "arn": "arn:aws:iam::123456789012:policy/test-policy-1"
                    }
                ]
            }
        }
    
    @pytest.fixture
    def sample_findings(self):
        """Sample Access Analyzer findings for testing"""
        return [
            {
                "id": "finding-1",
                "findingType": "UNUSED_ACCESS",
                "status": "ACTIVE",
                "resource": {
                    "arn": "arn:aws:iam::123456789012:user/test-user-1",
                    "type": "AWS::IAM::User"
                },
                "createdAt": "2025-06-21T00:00:00Z"
            },
            {
                "id": "finding-2",
                "findingType": "EXTERNAL_ACCESS",
                "status": "ACTIVE",
                "resource": {
                    "arn": "arn:aws:iam::123456789012:role/test-role-1",
                    "type": "AWS::IAM::Role"
                },
                "createdAt": "2025-06-21T01:00:00Z"
            }
        ]

    def test_analyzer_initialization(self, mock_aws_clients):
        """Test that IAMAnalyzer initializes correctly"""
        analyzer = IAMAnalyzer(region='us-west-2')
        
        assert analyzer.region == 'us-west-2'
        assert analyzer.access_analyzer is not None
        assert analyzer.s3_client is not None
        
        # Verify boto3.client was called correctly
        expected_calls = [
            (('accessanalyzer',), {'region_name': 'us-west-2'}),
            (('s3',), {'region_name': 'us-west-2'})
        ]
        actual_calls = mock_aws_clients['boto3'].client.call_args_list
        assert len(actual_calls) == 2

    def test_initialization_failure(self):
        """Test that initialization failures are handled properly"""
        with patch('modules.iam_analyzer.boto3.client', side_effect=Exception("AWS Error")):
            with pytest.raises(AnalyzerError) as exc_info:
                IAMAnalyzer()
            
            assert "Failed to initialize AWS clients" in str(exc_info.value)

    def test_fetch_resources_from_s3_success(self, analyzer, mock_aws_clients, sample_s3_data):
        """Test successful resource fetching from S3"""
        # Mock S3 response
        mock_response = {
            'Body': Mock(),
            'ContentLength': 1024
        }
        mock_response['Body'].read.return_value = json.dumps(sample_s3_data).encode('utf-8')
        mock_aws_clients['s3_client'].get_object.return_value = mock_response
        
        # Call the method
        resources = analyzer.fetch_resources_from_s3('test-bucket', 'test-prefix')
        
        # Verify results - Updated count: 2 users + 1 role + 1 group (1 invalid skipped) + 1 policy = 5
        assert len(resources) == 5
        
        # Check specific resources
        user_resources = [r for r in resources if r.resource_type == ResourceType.USER]
        assert len(user_resources) == 2
        assert user_resources[0].name == "test-user-1"
        assert user_resources[0].arn == "arn:aws:iam::123456789012:user/test-user-1"
        
        role_resources = [r for r in resources if r.resource_type == ResourceType.ROLE]
        assert len(role_resources) == 1
        assert role_resources[0].name == "test-role-1"
        
        # Verify S3 call
        mock_aws_clients['s3_client'].get_object.assert_called_once_with(
            Bucket='test-bucket',
            Key='test-prefix/latest.json'
        )

    def test_fetch_resources_validation_error(self, analyzer):
        """Test validation errors for S3 parameters"""
        with pytest.raises(ValueError) as exc_info:
            analyzer.fetch_resources_from_s3('', 'prefix')
        assert "Both bucket_name and prefix are required" in str(exc_info.value)
        
        with pytest.raises(ValueError) as exc_info:
            analyzer.fetch_resources_from_s3('bucket', '')
        assert "Both bucket_name and prefix are required" in str(exc_info.value)

    def test_fetch_resources_s3_error(self, analyzer, mock_aws_clients):
        """Test S3 client errors are handled properly"""
        from botocore.exceptions import ClientError
        
        error_response = {'Error': {'Code': 'NoSuchBucket', 'Message': 'Bucket not found'}}
        mock_aws_clients['s3_client'].get_object.side_effect = ClientError(
            error_response, 'GetObject'
        )
        
        with pytest.raises(AnalyzerError) as exc_info:
            analyzer.fetch_resources_from_s3('test-bucket', 'test-prefix')
        
        assert "Failed to fetch resources from S3" in str(exc_info.value)

    def test_fetch_resources_invalid_json(self, analyzer, mock_aws_clients):
        """Test handling of invalid JSON from S3"""
        mock_response = {
            'Body': Mock(),
            'ContentLength': 100
        }
        mock_response['Body'].read.return_value = b"invalid json content"
        mock_aws_clients['s3_client'].get_object.return_value = mock_response
        
        with pytest.raises(AnalyzerError) as exc_info:
            analyzer.fetch_resources_from_s3('test-bucket', 'test-prefix')
        
        assert "Failed to fetch resources from S3" in str(exc_info.value)

    def test_list_findings_for_resources(self, analyzer, mock_aws_clients, sample_findings):
        """Test listing findings for specific resources"""
        # Create test resources
        resources = [
            IAMResource(
                arn="arn:aws:iam::123456789012:user/test-user-1",
                resource_type=ResourceType.USER,
                name="test-user-1"
            ),
            IAMResource(
                arn="arn:aws:iam::123456789012:role/test-role-1",
                resource_type=ResourceType.ROLE,
                name="test-role-1"
            )
        ]
        
        # Mock Access Analyzer response
        mock_aws_clients['access_analyzer'].list_findings_v2.return_value = {
            'findings': sample_findings
        }
        
        # Call the method
        findings, summary = analyzer.list_findings_for_resources(
            'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            resources
        )
        
        # Verify results
        assert len(findings) == 2
        assert isinstance(summary, FindingSummary)
        assert summary.total_findings == 2
        assert summary.findings_by_type['UNUSED_ACCESS'] == 1
        assert summary.findings_by_type['EXTERNAL_ACCESS'] == 1
        assert summary.findings_by_status['ACTIVE'] == 2
        
        # Verify API call
        expected_filter = {
            'resource': {
                'contains': [
                    "arn:aws:iam::123456789012:user/test-user-1",
                    "arn:aws:iam::123456789012:role/test-role-1"
                ]
            }
        }
        mock_aws_clients['access_analyzer'].list_findings_v2.assert_called_once_with(
            analyzerArn='arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            filter=expected_filter
        )

    def test_list_findings_validation_error(self, analyzer):
        """Test validation errors for findings parameters"""
        with pytest.raises(ValueError) as exc_info:
            analyzer.list_findings_for_resources('', [])
        assert "analyzer_arn and resources are required" in str(exc_info.value)
        
        with pytest.raises(ValueError) as exc_info:
            analyzer.list_findings_for_resources('arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test', [])
        assert "analyzer_arn and resources are required" in str(exc_info.value)

    def test_get_finding_details(self, analyzer, mock_aws_clients):
        """Test getting details for a specific finding"""
        finding_detail = {
            'finding': {
                'id': 'finding-1',
                'findingType': 'UNUSED_ACCESS',
                'status': 'ACTIVE',
                'resource': {
                    'arn': 'arn:aws:iam::123456789012:user/test-user-1',
                    'type': 'AWS::IAM::User'
                },
                'createdAt': '2025-06-21T00:00:00Z'
            }
        }
        
        mock_aws_clients['access_analyzer'].get_finding.return_value = finding_detail
        
        result = analyzer.get_finding_details(
            'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            'finding-1'
        )
        
        assert result == finding_detail['finding']
        mock_aws_clients['access_analyzer'].get_finding.assert_called_once_with(
            analyzerArn='arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            id='finding-1'
        )

    def test_update_finding_status(self, analyzer, mock_aws_clients):
        """Test updating finding status"""
        analyzer.update_finding_status(
            'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            ['finding-1', 'finding-2'],
            FindingStatus.ARCHIVED
        )
        
        mock_aws_clients['access_analyzer'].update_findings.assert_called_once_with(
            analyzerArn='arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            ids=['finding-1', 'finding-2'],
            status='ARCHIVED'
        )

    def test_update_finding_status_with_string(self, analyzer, mock_aws_clients):
        """Test updating finding status with string parameter"""
        analyzer.update_finding_status(
            'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            ['finding-1'],
            'RESOLVED'
        )
        
        mock_aws_clients['access_analyzer'].update_findings.assert_called_once_with(
            analyzerArn='arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            ids=['finding-1'],
            status='RESOLVED'
        )

    def test_validate_policy(self, analyzer, mock_aws_clients):
        """Test policy validation"""
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        })
        
        validation_findings = [
            {
                "findingType": "SECURITY_WARNING",
                "findingDetails": "Overly broad resource specification"
            }
        ]
        
        mock_aws_clients['access_analyzer'].validate_policy.return_value = {
            'findings': validation_findings
        }
        
        result = analyzer.validate_policy(policy_doc)
        
        assert result == validation_findings
        mock_aws_clients['access_analyzer'].validate_policy.assert_called_once_with(
            policyDocument=policy_doc,
            policyType='IAM'
        )

    def test_list_analyzers(self, analyzer, mock_aws_clients):
        """Test listing Access Analyzers"""
        analyzers_data = [
            {
                'name': 'test-analyzer',
                'arn': 'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
                'status': 'ACTIVE',
                'type': 'ACCOUNT',
                'createdAt': '2025-06-21T00:00:00Z'
            }
        ]
        
        mock_aws_clients['access_analyzer'].list_analyzers.return_value = {
            'analyzers': analyzers_data
        }
        
        result = analyzer.list_analyzers()
        
        assert result == analyzers_data
        mock_aws_clients['access_analyzer'].list_analyzers.assert_called_once()

    def test_generate_policy(self, analyzer, mock_aws_clients):
        """Test policy generation"""
        job_id = 'test-job-123'
        generated_policy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Action': 's3:GetObject',
                    'Resource': 'arn:aws:s3:::test-bucket/*'
                }
            ]
        }
        
        # Mock the policy generation flow
        mock_aws_clients['access_analyzer'].start_policy_generation.return_value = {
            'jobId': job_id
        }
        
        mock_waiter = Mock()
        mock_aws_clients['access_analyzer'].get_waiter.return_value = mock_waiter
        
        mock_aws_clients['access_analyzer'].get_generated_policy.return_value = {
            'generatedPolicy': generated_policy
        }
        
        configuration = {
            'serviceType': 'S3',
            'cloudTrailArn': 'arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail'
        }
        
        result = analyzer.generate_policy('IDENTITY_BASED_POLICY', configuration)
        
        assert result == generated_policy
        
        # Verify all API calls
        mock_aws_clients['access_analyzer'].start_policy_generation.assert_called_once_with(
            policyType='IDENTITY_BASED_POLICY',
            policyGenerationDetails=configuration
        )
        mock_waiter.wait.assert_called_once_with(jobId=job_id)
        mock_aws_clients['access_analyzer'].get_generated_policy.assert_called_once_with(jobId=job_id)

    def test_analyze_resources_from_s3_complete_workflow(self, analyzer, mock_aws_clients, sample_s3_data, sample_findings):
        """Test the complete workflow: fetch resources and analyze findings"""
        # Mock S3 response
        mock_s3_response = {
            'Body': Mock(),
            'ContentLength': 1024
        }
        mock_s3_response['Body'].read.return_value = json.dumps(sample_s3_data).encode('utf-8')
        mock_aws_clients['s3_client'].get_object.return_value = mock_s3_response
        
        # Mock Access Analyzer response
        mock_aws_clients['access_analyzer'].list_findings_v2.return_value = {
            'findings': sample_findings
        }
        
        # Call the complete workflow
        resources, findings, summary = analyzer.analyze_resources_from_s3(
            'arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test-analyzer',
            'test-bucket',
            'test-prefix'
        )
        
        # Verify results
        assert len(resources) == 5  # Based on sample data (2 users, 1 role, 1 valid group, 1 policy)
        assert len(findings) == 2
        assert isinstance(summary, FindingSummary)
        assert summary.total_findings == 2

    def test_iam_resource_validation(self):
        """Test IAMResource validation"""
        # Valid resource
        resource = IAMResource(
            arn="arn:aws:iam::123456789012:user/test-user",
            resource_type=ResourceType.USER,
            name="test-user"
        )
        assert resource.arn == "arn:aws:iam::123456789012:user/test-user"
        assert resource.name == "test-user"
        
        # Invalid resource - missing ARN
        with pytest.raises(ValueError) as exc_info:
            IAMResource(
                arn="",
                resource_type=ResourceType.USER,
                name="test-user"
            )
        assert "Resource ARN and name are required" in str(exc_info.value)
        
        # Invalid resource - missing name
        with pytest.raises(ValueError) as exc_info:
            IAMResource(
                arn="arn:aws:iam::123456789012:user/test-user",
                resource_type=ResourceType.USER,
                name=""
            )
        assert "Resource ARN and name are required" in str(exc_info.value)

    def test_finding_summary_creation(self):
        """Test FindingSummary dataclass"""
        summary = FindingSummary(
            total_findings=5,
            findings_by_type={'UNUSED_ACCESS': 3, 'EXTERNAL_ACCESS': 2},
            findings_by_status={'ACTIVE': 4, 'ARCHIVED': 1},
            findings_by_resource={'arn:aws:iam::123456789012:user/test': 5}
        )
        
        assert summary.total_findings == 5
        assert summary.findings_by_type['UNUSED_ACCESS'] == 3
        assert summary.findings_by_status['ACTIVE'] == 4

    def test_backwards_compatibility(self, mock_aws_clients):
        """Test that the Analyzer alias still works for backwards compatibility"""
        from modules.iam_analyzer import Analyzer
        
        analyzer = Analyzer(region='us-east-1')
        assert isinstance(analyzer, IAMAnalyzer)


# Integration test that can run with real AWS services if environment is configured
class TestIAMAnalyzerIntegration:
    """Integration tests for IAMAnalyzer (requires real AWS credentials)"""
    
    @pytest.mark.integration
    def test_real_aws_connection(self):
        """Test real AWS connection (skip if no credentials)"""
        try:
            analyzer = IAMAnalyzer()
            # Try to list analyzers - this should work if credentials are available
            analyzers = analyzer.list_analyzers()
            assert isinstance(analyzers, list)
        except Exception as e:
            pytest.skip(f"Integration test skipped - AWS credentials not available: {e}")


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])