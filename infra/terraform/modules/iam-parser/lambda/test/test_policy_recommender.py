"""
Test suite for the refactored PolicyRecommender class

This test suite validates the cleaned-up PolicyRecommender functionality
with improved modularity, error handling, and focused alice-analyst-test processing.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any

# Add the src directory to the path
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from modules.policy_recommender import PolicyRecommender, PolicyRecommenderError, FindingProcessingError, GitHubOperationError


class TestPolicyRecommender:
    """Test suite for refactored PolicyRecommender class"""
    
    @pytest.fixture
    def mock_github_setup(self):
        """Setup mocked GitHub client"""
        with patch('modules.policy_recommender.Github') as mock_github_class:
            mock_github = Mock()
            mock_repo = Mock()
            mock_github_class.return_value = mock_github
            mock_github.get_repo.return_value = mock_repo
            
            yield {
                'github_class': mock_github_class,
                'github': mock_github,
                'repo': mock_repo
            }
    
    @pytest.fixture
    def mock_boto3_setup(self):
        """Setup mocked boto3 client"""
        with patch('modules.policy_recommender.boto3') as mock_boto3:
            mock_access_analyzer = Mock()
            mock_boto3.client.return_value = mock_access_analyzer
            
            yield {
                'boto3': mock_boto3,
                'access_analyzer': mock_access_analyzer
            }
    
    @pytest.fixture
    def policy_recommender(self, mock_github_setup, mock_boto3_setup):
        """Create a PolicyRecommender instance for testing"""
        return PolicyRecommender(
            github_token="test_token",
            repo_name="test_owner/test_repo",
            region="us-east-1"
        )
    
    @pytest.fixture
    def sample_alice_finding(self):
        """Sample alice-analyst-test finding"""
        return {
            'id': 'alice-finding-123',
            'findingType': 'UNUSED_ACCESS',
            'resource': {
                'arn': 'arn:aws:iam::123456789012:user/alice-analyst-test'
            },
            'status': 'ACTIVE'
        }
    
    @pytest.fixture
    def sample_other_finding(self):
        """Sample non-alice finding"""
        return {
            'id': 'other-finding-456',
            'findingType': 'UNUSED_ACCESS',
            'resource': {
                'arn': 'arn:aws:iam::123456789012:user/other-user'
            },
            'status': 'ACTIVE'
        }
    
    @pytest.fixture
    def sample_resources(self):
        """Sample IAM resources"""
        return [
            {
                "ResourceARN": "arn:aws:iam::123456789012:user/alice-analyst-test",
                "ResourceType": "AWS::IAM::User",
                "ResourceName": "alice-analyst-test",
                "tf_resource_name": "alice_analyst_test"
            },
            {
                "ResourceARN": "arn:aws:iam::123456789012:user/other-user",
                "ResourceType": "AWS::IAM::User", 
                "ResourceName": "other-user",
                "tf_resource_name": "other_user"
            }
        ]

    def test_initialization_success(self, mock_github_setup, mock_boto3_setup):
        """Test successful PolicyRecommender initialization"""
        recommender = PolicyRecommender(
            github_token="test_token",
            repo_name="test_owner/test_repo",
            region="us-west-2"
        )
        
        assert recommender.github_token == "test_token"
        assert recommender.repo_name == "test_owner/test_repo"
        assert recommender.region == "us-west-2"
        
        # Verify clients were initialized
        mock_github_setup['github_class'].assert_called_once()
        mock_boto3_setup['boto3'].client.assert_called_with('accessanalyzer', region_name='us-west-2')

    def test_initialization_failure(self):
        """Test PolicyRecommender initialization failure"""
        with patch('modules.policy_recommender.Github', side_effect=Exception("GitHub error")):
            with pytest.raises(PolicyRecommenderError) as exc_info:
                PolicyRecommender(
                    github_token="test_token",
                    repo_name="test_owner/test_repo"
                )
            
            assert "Failed to initialize PolicyRecommender" in str(exc_info.value)

    def test_extract_resource_arn_dict(self, policy_recommender):
        """Test extracting resource ARN from dictionary format"""
        finding = {
            'resource': {
                'arn': 'arn:aws:iam::123456789012:user/test-user'
            }
        }
        
        arn = policy_recommender._extract_resource_arn(finding)
        assert arn == "arn:aws:iam::123456789012:user/test-user"

    def test_extract_resource_arn_string(self, policy_recommender):
        """Test extracting resource ARN from string format"""
        finding = {
            'resource': 'arn:aws:iam::123456789012:user/test-user'
        }
        
        arn = policy_recommender._extract_resource_arn(finding)
        assert arn == "arn:aws:iam::123456789012:user/test-user"

    def test_extract_resource_arn_missing(self, policy_recommender):
        """Test extracting resource ARN when missing"""
        finding = {}
        
        arn = policy_recommender._extract_resource_arn(finding)
        assert arn == "unknown"

    def test_should_process_finding_with_unused_actions(self, policy_recommender):
        """Test should_process_finding with unused actions"""
        finding = {'id': 'test'}
        unused_actions = ['s3:GetObject']
        
        result = policy_recommender._should_process_finding(finding, unused_actions)
        assert result is True

    def test_should_process_finding_alice_without_actions(self, policy_recommender):
        """Test should_process_finding for alice-analyst-test without unused actions"""
        finding = {
            'id': 'test',
            'resource': {
                'arn': 'arn:aws:iam::123456789012:user/alice-analyst-test'
            }
        }
        unused_actions = []
        
        result = policy_recommender._should_process_finding(finding, unused_actions)
        assert result is True

    def test_should_not_process_finding_other_user(self, policy_recommender):
        """Test should_process_finding for other users without unused actions"""
        finding = {
            'id': 'test',
            'resource': {
                'arn': 'arn:aws:iam::123456789012:user/other-user'
            }
        }
        unused_actions = []
        
        result = policy_recommender._should_process_finding(finding, unused_actions)
        assert result is False

    def test_generate_fallback_unused_actions(self, policy_recommender):
        """Test generating fallback unused actions"""
        actions = policy_recommender._generate_fallback_unused_actions()
        
        assert len(actions) > 0
        assert "s3:*" in actions
        assert "iam:List*" in actions
        assert "sts:AssumeRole" in actions

    def test_create_fallback_finding_for_alice(self, policy_recommender, sample_alice_finding):
        """Test creating fallback finding for alice-analyst-test"""
        fallback = policy_recommender._create_fallback_finding(sample_alice_finding)
        
        assert fallback is not None
        assert fallback['id'] == 'alice-finding-123'
        assert fallback['finding_type'] == 'UNUSED_ACCESS'
        assert len(fallback['unused_actions']) > 0

    def test_create_fallback_finding_for_other(self, policy_recommender, sample_other_finding):
        """Test creating fallback finding for non-alice user (should return None)"""
        fallback = policy_recommender._create_fallback_finding(sample_other_finding)
        assert fallback is None

    def test_extract_unused_actions_from_v2_response(self, policy_recommender):
        """Test extracting unused actions from V2 response"""
        response = {
            'finding': {
                'findingDetails': [
                    {
                        'unusedPermissionDetails': {
                            'serviceNamespace': 's3',
                            'actions': ['s3:GetObject', 's3:PutObject']
                        }
                    },
                    {
                        'unusedPermissionDetails': {
                            'serviceNamespace': 'iam',
                            'actions': []
                        }
                    }
                ]
            }
        }
        
        actions = policy_recommender._extract_unused_actions_from_v2_response(response)
        
        assert 's3:GetObject' in actions
        assert 's3:PutObject' in actions
        assert 'iam:*' in actions  # Generated for service without specific actions

    def test_extract_unused_actions_from_standard_response(self, policy_recommender):
        """Test extracting unused actions from standard response"""
        detailed_finding = {
            'findingDetails': {
                'unusedPermissionDetails': [
                    {'actions': ['ec2:DescribeInstances']},
                    {'actions': 'lambda:InvokeFunction'}
                ]
            }
        }
        
        actions = policy_recommender._extract_unused_actions_from_standard_response(detailed_finding)
        
        assert 'ec2:DescribeInstances' in actions
        assert 'lambda:InvokeFunction' in actions

    def test_create_resource_lookup(self, policy_recommender, sample_resources):
        """Test creating resource lookup dictionary"""
        lookup = policy_recommender._create_resource_lookup(sample_resources)
        
        assert len(lookup) == 2
        assert "arn:aws:iam::123456789012:user/alice-analyst-test" in lookup
        assert "arn:aws:iam::123456789012:user/other-user" in lookup

    def test_process_single_finding_alice(self, policy_recommender, sample_resources):
        """Test processing a single finding for alice-analyst-test"""
        finding = {
            'id': 'alice-finding-123',
            'resource_arn': 'arn:aws:iam::123456789012:user/alice-analyst-test',
            'finding_type': 'UNUSED_ACCESS',
            'unused_actions': ['s3:GetObject', 'iam:List*']
        }
        
        resource_lookup = policy_recommender._create_resource_lookup(sample_resources)
        result = policy_recommender._process_single_finding(finding, resource_lookup)
        
        assert result is not None
        resource_key, recommendation = result
        
        assert resource_key == "aws_iam_user.alice_analyst_test"
        assert recommendation['finding_id'] == 'alice-finding-123'
        assert recommendation['resource_name'] == 'alice-analyst-test'
        assert len(recommendation['unused_actions']) == 2
        assert recommendation['confidence'] == 'high'

    def test_process_single_finding_other_user(self, policy_recommender, sample_resources):
        """Test processing a single finding for non-alice user (should skip)"""
        finding = {
            'id': 'other-finding-456',
            'resource_arn': 'arn:aws:iam::123456789012:user/other-user',
            'finding_type': 'UNUSED_ACCESS',
            'unused_actions': ['s3:GetObject']
        }
        
        resource_lookup = policy_recommender._create_resource_lookup(sample_resources)
        result = policy_recommender._process_single_finding(finding, resource_lookup)
        
        assert result is None

    def test_process_detailed_findings_success(self, policy_recommender, sample_resources):
        """Test processing detailed findings successfully"""
        detailed_findings = [
            {
                'id': 'alice-finding-123',
                'resource_arn': 'arn:aws:iam::123456789012:user/alice-analyst-test',
                'finding_type': 'UNUSED_ACCESS',
                'unused_actions': ['s3:*', 'iam:Get*']
            }
        ]
        
        recommendations = policy_recommender.process_detailed_findings(detailed_findings, sample_resources)
        
        assert len(recommendations) == 1
        assert "aws_iam_user.alice_analyst_test" in recommendations
        
        rec = recommendations["aws_iam_user.alice_analyst_test"]
        assert rec['resource_name'] == 'alice-analyst-test'
        assert len(rec['unused_actions']) == 2

    def test_process_detailed_findings_empty(self, policy_recommender, sample_resources):
        """Test processing empty detailed findings"""
        recommendations = policy_recommender.process_detailed_findings([], sample_resources)
        assert recommendations == {}

    def test_generate_modification_header(self, policy_recommender):
        """Test generating modification header"""
        recommendations = {
            "aws_iam_user.alice_analyst_test": {
                'finding_id': 'test-123',
                'unused_actions': ['s3:*', 'iam:Get*']
            }
        }
        
        header = policy_recommender._generate_modification_header("2025-06-22 12:00:00 UTC", recommendations)
        
        assert "MODIFIED BY LEAST PRIVILEGE OPTIMIZER - 2025-06-22 12:00:00 UTC" in header
        assert "Finding ID: test-123" in header
        assert "Unused actions: 2" in header

    def test_generate_minimal_policy_block(self, policy_recommender):
        """Test generating minimal policy block"""
        policy_block = policy_recommender._generate_minimal_policy_block()
        
        assert 'resource "aws_iam_user_policy" "alice_analyst_policy"' in policy_block
        assert '"alice-analyst-test-policy"' in policy_block
        assert 'Statement = []' in policy_block

    def test_modify_policies_content(self, policy_recommender):
        """Test modifying policies.tf content"""
        original_content = '''resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = ["s3:*", "iam:*"],
        Resource = "*"
      }
    ]
  })
}'''
        
        recommendations = {
            "aws_iam_user.alice_analyst_test": {
                'finding_id': 'test-123',
                'unused_actions': ['s3:*', 'iam:*']
            }
        }
        
        modified_content = policy_recommender._modify_policies_content(original_content, recommendations)
        
        assert "MODIFIED BY LEAST PRIVILEGE OPTIMIZER" in modified_content
        assert "Statement = []" in modified_content
        assert "Finding ID: test-123" in modified_content

    @patch('modules.policy_recommender.datetime')
    def test_generate_pr_content(self, mock_datetime, policy_recommender):
        """Test generating PR title and body"""
        mock_datetime.now.return_value.strftime.return_value = "2025-06-22 12:00:00 UTC"
        
        recommendations = {
            "aws_iam_user.alice_analyst_test": {
                'finding_id': 'test-123',
                'resource_name': 'alice-analyst-test',
                'unused_actions': ['s3:*', 'iam:Get*'],
                'confidence': 'high'
            }
        }
        
        title, body = policy_recommender._generate_pr_content(recommendations)
        
        assert title == "🔒 Remove unused IAM permissions for least privilege"
        assert "AWS IAM Access Analyzer Integration" in body
        assert "Finding ID:** `test-123`" in body
        assert "Unused Actions:** 2 permissions removed" in body
        assert "2025-06-22 12:00:00 UTC" in body

    @patch('modules.policy_recommender.base64')
    def test_download_policies_file_success(self, mock_base64, policy_recommender, mock_github_setup):
        """Test successful download of policies.tf file"""
        # Setup mock file content
        mock_file_content = Mock()
        mock_file_content.content = b"encoded_content"
        mock_github_setup['repo'].get_contents.return_value = mock_file_content
        mock_base64.b64decode.return_value.decode.return_value = "decoded_content"
        
        content = policy_recommender._download_policies_file()
        
        assert content == "decoded_content"
        mock_github_setup['repo'].get_contents.assert_called()

    def test_download_policies_file_failure(self, policy_recommender, mock_github_setup):
        """Test failed download of policies.tf file"""
        mock_github_setup['repo'].get_contents.side_effect = Exception("File not found")
        
        content = policy_recommender._download_policies_file()
        assert content is None

    @patch('modules.policy_recommender.datetime')
    def test_create_github_pr_success(self, mock_datetime, policy_recommender, mock_github_setup):
        """Test successful GitHub PR creation"""
        mock_datetime.now.return_value.strftime.return_value = "20250622-120000"
        
        # Setup mocks
        mock_main_branch = Mock()
        mock_main_branch.commit.sha = "abc123"
        mock_github_setup['repo'].get_branch.return_value = mock_main_branch
        
        mock_existing_file = Mock()
        mock_existing_file.sha = "def456"
        mock_github_setup['repo'].get_contents.return_value = mock_existing_file
        
        mock_pr = Mock()
        mock_pr.number = 42
        mock_pr.html_url = "https://github.com/test/repo/pull/42"
        mock_github_setup['repo'].create_pull.return_value = mock_pr
        
        recommendations = {
            "aws_iam_user.alice_analyst_test": {
                'finding_id': 'test-123',
                'resource_name': 'alice-analyst-test',
                'unused_actions': ['s3:*'],
                'confidence': 'high'
            }
        }
        
        result = policy_recommender._create_github_pr("modified_content", recommendations)
        
        assert result is True
        mock_github_setup['repo'].create_git_ref.assert_called()
        mock_github_setup['repo'].update_file.assert_called()
        mock_github_setup['repo'].create_pull.assert_called()

    def test_create_github_pr_failure(self, policy_recommender, mock_github_setup):
        """Test GitHub PR creation failure"""
        mock_github_setup['repo'].get_branch.side_effect = Exception("Branch error")
        
        recommendations = {
            "aws_iam_user.alice_analyst_test": {
                'finding_id': 'test-123',
                'resource_name': 'alice-analyst-test',
                'unused_actions': ['s3:*'],
                'confidence': 'high'
            }
        }
        
        with pytest.raises(GitHubOperationError):
            policy_recommender._create_github_pr("modified_content", recommendations)


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])