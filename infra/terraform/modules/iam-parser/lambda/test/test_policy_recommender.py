"""
Test suite for the PolicyRecommender class

This test suite validates the enhanced PolicyRecommender functionality
including recommendation generation, Terraform file creation, and GitHub PR integration.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any

# Add the src directory to the path
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from modules.policy_recommender import PolicyRecommender
from modules.iam_analyzer import IAMResource, ResourceType


class TestPolicyRecommender:
    """Test suite for PolicyRecommender class"""
    
    @pytest.fixture
    def policy_recommender(self):
        """Create a PolicyRecommender instance for testing"""
        return PolicyRecommender(
            github_token="test_token",
            repo_name="test_owner/test_repo"
        )
    
    @pytest.fixture
    def sample_resources_dict(self):
        """Sample resources in dictionary format"""
        return [
            {
                "ResourceARN": "arn:aws:iam::123456789012:user/test-user",
                "ResourceType": "AWS::IAM::User",
                "ResourceName": "test-user",
                "tf_resource_name": "test_user"
            },
            {
                "ResourceARN": "arn:aws:iam::123456789012:role/test-role",
                "ResourceType": "AWS::IAM::Role", 
                "ResourceName": "test-role",
                "tf_resource_name": "test_role"
            }
        ]
    
    @pytest.fixture
    def sample_resources_objects(self):
        """Sample resources as IAMResource objects"""
        return [
            IAMResource(
                arn="arn:aws:iam::123456789012:user/test-user",
                resource_type=ResourceType.USER,
                name="test-user"
            ),
            IAMResource(
                arn="arn:aws:iam::123456789012:role/test-role",
                resource_type=ResourceType.ROLE,
                name="test-role"
            )
        ]
    
    @pytest.fixture
    def sample_findings_with_policies(self):
        """Sample findings with policy data"""
        return [
            {
                "id": "finding-1",
                "findingType": "UNUSED_ACCESS",
                "status": "ACTIVE",
                "resource": {
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                    "type": "AWS::IAM::User",
                    "policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:*", "ec2:*"],
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
                            "Resource": ["arn:aws:s3:::test-bucket/*", "arn:aws:s3:::test-bucket"]
                        }
                    ]
                },
                "findingDetails": {
                    "unusedActions": ["ec2:*", "s3:PutObject", "s3:DeleteObject"]
                }
            }
        ]
    
    @pytest.fixture
    def sample_findings_string_resource(self):
        """Sample findings where resource is a string (ARN)"""
        return [
            {
                "id": "finding-2",
                "findingType": "EXTERNAL_ACCESS",
                "status": "ACTIVE",
                "resource": "arn:aws:iam::123456789012:role/test-role",
                "findingDetails": {
                    "externalPrincipal": "123456789999"
                }
            }
        ]
    
    @pytest.fixture
    def sample_findings_no_policy(self):
        """Sample findings with no policy data"""
        return [
            {
                "id": "finding-3",
                "findingType": "UNUSED_IAM_ROLE",
                "status": "ACTIVE",
                "resource": {
                    "arn": "arn:aws:iam::123456789012:role/test-role",
                    "type": "AWS::IAM::Role"
                },
                "findingDetails": {
                    "lastUsed": "2025-01-01T00:00:00Z"
                }
            }
        ]
    
    @pytest.fixture
    def sample_findings_analyzed_policy_only(self):
        """Sample findings with only analyzed policy"""
        return [
            {
                "id": "finding-4",
                "findingType": "UNUSED_ACCESS",
                "status": "ACTIVE",
                "resource": {
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                    "type": "AWS::IAM::User"
                },
                "analyzedPolicy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": "arn:aws:s3:::test-bucket/*"
                        }
                    ]
                }
            }
        ]

    def test_extract_resource_arn_dict(self, policy_recommender):
        """Test extracting resource ARN from dictionary format"""
        finding = {
            "id": "test-finding",
            "resource": {
                "arn": "arn:aws:iam::123456789012:user/test-user",
                "type": "AWS::IAM::User"
            }
        }
        
        arn = policy_recommender._extract_resource_arn(finding)
        assert arn == "arn:aws:iam::123456789012:user/test-user"

    def test_extract_resource_arn_string(self, policy_recommender):
        """Test extracting resource ARN from string format"""
        finding = {
            "id": "test-finding",
            "resource": "arn:aws:iam::123456789012:user/test-user"
        }
        
        arn = policy_recommender._extract_resource_arn(finding)
        assert arn == "arn:aws:iam::123456789012:user/test-user"

    def test_extract_resource_arn_missing(self, policy_recommender):
        """Test extracting resource ARN when missing"""
        finding = {
            "id": "test-finding"
        }
        
        arn = policy_recommender._extract_resource_arn(finding)
        assert arn == "unknown"

    def test_extract_resource_policy_dict(self, policy_recommender):
        """Test extracting policy from dictionary resource"""
        finding = {
            "id": "test-finding",
            "resource": {
                "arn": "arn:aws:iam::123456789012:user/test-user",
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": []
                }
            }
        }
        
        policy = policy_recommender._extract_resource_policy(finding)
        assert policy["Version"] == "2012-10-17"

    def test_extract_resource_policy_string(self, policy_recommender):
        """Test extracting policy from string resource (should return empty)"""
        finding = {
            "id": "test-finding",
            "resource": "arn:aws:iam::123456789012:user/test-user"
        }
        
        policy = policy_recommender._extract_resource_policy(finding)
        assert policy == {}

    def test_analyze_finding_structure(self, policy_recommender):
        """Test finding structure analysis"""
        finding = {
            "id": "test-finding",
            "findingType": "UNUSED_ACCESS",
            "resource": {
                "arn": "arn:aws:iam::123456789012:user/test-user",
                "policy": {"Version": "2012-10-17"}
            },
            "findingDetails": {
                "unusedActions": ["s3:PutObject"]
            }
        }
        
        analysis = policy_recommender._analyze_finding_structure(finding)
        
        assert analysis["finding_id"] == "test-finding"
        assert analysis["finding_type"] == "UNUSED_ACCESS"
        assert analysis["has_resource_field"] == True
        assert analysis["resource_type"] == "dict"
        assert analysis["has_policy_in_resource"] == True
        assert analysis["has_unused_actions"] == True
        assert analysis["unused_actions_count"] == 1

    def test_process_findings_with_dict_resources(self, policy_recommender, sample_resources_dict, sample_findings_with_policies):
        """Test processing findings with dictionary format resources"""
        recommendations = policy_recommender.process_findings(
            sample_findings_with_policies,
            sample_resources_dict
        )
        
        assert len(recommendations) == 1
        
        key = "aws_iam_user.test-user"
        assert key in recommendations
        
        rec = recommendations[key]
        assert rec["resource_name"] == "test-user"
        assert rec["resource_type"] == "AWS::IAM::User"
        assert rec["finding_type"] == "UNUSED_ACCESS"
        assert rec["recommendation_type"] == "policy_optimization"
        assert rec["confidence"] == "high"
        assert len(rec["unused_actions"]) == 3

    def test_process_findings_with_object_resources(self, policy_recommender, sample_resources_objects, sample_findings_with_policies):
        """Test processing findings with IAMResource objects"""
        recommendations = policy_recommender.process_findings(
            sample_findings_with_policies,
            sample_resources_objects
        )
        
        assert len(recommendations) == 1
        
        key = "aws_iam_user.test-user"
        assert key in recommendations
        
        rec = recommendations[key]
        assert rec["resource_name"] == "test-user"
        assert rec["resource_type"] == "AWS::IAM::User"

    def test_process_findings_string_resource(self, policy_recommender, sample_resources_dict, sample_findings_string_resource):
        """Test processing findings with string resource format"""
        recommendations = policy_recommender.process_findings(
            sample_findings_string_resource,
            sample_resources_dict
        )
        
        assert len(recommendations) == 1
        
        key = "aws_iam_role.test-role"
        assert key in recommendations
        
        rec = recommendations[key]
        assert rec["finding_type"] == "EXTERNAL_ACCESS"
        assert rec["recommendation_type"] == "security_review"
        assert rec["action_required"] == "manual_review"

    def test_process_findings_no_policy(self, policy_recommender, sample_resources_dict, sample_findings_no_policy):
        """Test processing findings without policy data"""
        recommendations = policy_recommender.process_findings(
            sample_findings_no_policy,
            sample_resources_dict
        )
        
        assert len(recommendations) == 1
        
        key = "aws_iam_role.test-role"
        assert key in recommendations
        
        rec = recommendations[key]
        assert rec["finding_type"] == "UNUSED_IAM_ROLE"
        assert rec["recommendation_type"] == "removal_candidate"
        assert rec["action_required"] == "review_for_removal"

    def test_process_findings_analyzed_policy_only(self, policy_recommender, sample_resources_dict, sample_findings_analyzed_policy_only):
        """Test processing findings with only analyzed policy"""
        recommendations = policy_recommender.process_findings(
            sample_findings_analyzed_policy_only,
            sample_resources_dict
        )
        
        assert len(recommendations) == 1
        
        key = "aws_iam_user.test-user"
        assert key in recommendations
        
        rec = recommendations[key]
        assert rec["recommendation_type"] == "least_privilege_suggestion"
        assert rec["confidence"] == "high"
        assert rec["recommended_policy"]["Statement"][0]["Action"] == ["s3:GetObject"]

    def test_generate_terraform_content_policy_optimization(self, policy_recommender):
        """Test generating Terraform content for policy optimization"""
        recommendation = {
            "recommendation_type": "policy_optimization",
            "resource_name": "test-user",
            "tf_resource_name": "test_user",
            "recommended_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "arn:aws:s3:::test-bucket/*"
                    }
                ]
            }
        }
        
        content = policy_recommender._generate_terraform_content("aws_iam_user.test-user", recommendation)
        
        assert content is not None
        assert 'resource "aws_iam_policy" "least_privilege_test_user"' in content
        assert '"s3:GetObject"' in content
        assert "LeastPrivilegeOptimizer" in content

    def test_generate_terraform_content_security_review(self, policy_recommender):
        """Test generating Terraform content for security review"""
        recommendation = {
            "recommendation_type": "security_review",
            "finding_id": "finding-123",
            "finding_type": "EXTERNAL_ACCESS",
            "recommendation_reason": "External access detected",
            "action_required": "manual_review",
            "unused_actions": ["s3:PutObject", "ec2:TerminateInstances"]
        }
        
        content = policy_recommender._generate_terraform_content("aws_iam_role.test-role", recommendation)
        
        assert content is not None
        assert "# Access Analyzer Finding: finding-123" in content
        assert "# MANUAL REVIEW REQUIRED" in content
        assert "# External access detected" in content
        assert "# Unused Actions Detected (2):" in content
        assert "#   - s3:PutObject" in content

    def test_generate_policy_json(self, policy_recommender):
        """Test generating policy JSON"""
        recommendation = {
            "recommended_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "*"
                    }
                ]
            }
        }
        
        policy_json = policy_recommender._generate_policy_json(recommendation)
        
        assert policy_json is not None
        assert policy_json["Version"] == "2012-10-17"
        assert len(policy_json["Statement"]) == 1

    def test_generate_policy_json_empty(self, policy_recommender):
        """Test generating policy JSON with empty recommendation"""
        recommendation = {
            "recommended_policy": {}
        }
        
        policy_json = policy_recommender._generate_policy_json(recommendation)
        assert policy_json is None

    def test_get_terraform_file_path(self, policy_recommender):
        """Test generating Terraform file paths"""
        # Policy optimization
        rec1 = {"recommendation_type": "policy_optimization", "tf_resource_name": "test_user"}
        path1 = policy_recommender._get_terraform_file_path("aws_iam_user.test-user", rec1)
        assert path1 == "terraform/policies/least_privilege_test_user.tf"
        
        # Security review
        rec2 = {"recommendation_type": "security_review", "tf_resource_name": "test_role"}
        path2 = policy_recommender._get_terraform_file_path("aws_iam_role.test-role", rec2)
        assert path2 == "terraform/reviews/review_test_role.tf"

    def test_get_policy_file_path(self, policy_recommender):
        """Test generating policy file paths"""
        recommendation = {"tf_resource_name": "test_user"}
        path = policy_recommender._get_policy_file_path("aws_iam_user.test-user", recommendation)
        assert path == "policies/generated/least_privilege_test_user.json"

    @patch('modules.policy_recommender.PolicyRecommender._get_timestamp')
    def test_generate_pr_content(self, mock_timestamp, policy_recommender):
        """Test generating PR title and body"""
        mock_timestamp.return_value = "20250621-120000"
        
        recommendations = {
            "aws_iam_user.test1": {"recommendation_type": "policy_optimization"},
            "aws_iam_role.test2": {"recommendation_type": "security_review"}
        }
        
        summary_stats = {
            "total_recommendations": 2,
            "by_type": {"policy_optimization": 1, "security_review": 1},
            "by_confidence": {"high": 1, "medium": 1},
            "by_action_required": {"policy_optimization": 1, "manual_review": 1}
        }
        
        title, body = policy_recommender._generate_pr_content(recommendations, summary_stats)
        
        assert "IAM Policy Updates - 2 Access Analyzer Recommendations" in title
        assert "**Total Recommendations**: 2" in body
        assert "**Policy Optimization**: 1" in body
        assert "**Security Review**: 1" in body
        assert "terraform plan" in body
        assert "Generated at: 20250621-120000" in body

    @patch('modules.policy_recommender.PolicyRecommender._get_timestamp')
    @patch('modules.github_pr.GitHubPRHandler')  # Mock the actual module location
    def test_update_terraform_policies_success(self, mock_github_handler_class, mock_timestamp, policy_recommender):
        """Test successful Terraform policy update with PR creation"""
        mock_timestamp.return_value = "20250621-120000"
        
        # Mock GitHub handler
        mock_github_handler = Mock()
        mock_github_handler.create_pull_request.return_value = {
            "status": "success",
            "pr_number": 123,
            "pr_url": "https://github.com/test_owner/test_repo/pull/123"
        }
        mock_github_handler_class.return_value = mock_github_handler
        
        # Sample recommendations
        recommendations = {
            "aws_iam_user.test_user": {
                "recommendation_type": "policy_optimization",
                "resource_name": "test-user",
                "tf_resource_name": "test_user",
                "finding_type": "UNUSED_ACCESS",
                "confidence": "high",
                "action_required": "policy_optimization",
                "recommendation_reason": "Remove unused permissions",
                "recommended_policy": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]
                },
                "unused_actions": ["s3:PutObject"]
            }
        }
        
        result = policy_recommender.update_terraform_policies(recommendations)
        
        assert result == True
        
        # Verify GitHub handler was called correctly
        mock_github_handler_class.assert_called_once_with(
            github_token="test_token",
            repo_name="test_owner/test_repo"
        )
        
        # Verify PR creation was called
        mock_github_handler.create_pull_request.assert_called_once()
        call_args = mock_github_handler.create_pull_request.call_args
        assert call_args[1]["base_branch"] == "main"
        assert call_args[1]["head_branch"] == "iam-policy-updates-20250621-120000"
        assert "IAM Policy Updates - 1 Access Analyzer Recommendations" in call_args[1]["title"]

    @patch('modules.github_pr.GitHubPRHandler')  # Mock the actual module location
    def test_update_terraform_policies_failure(self, mock_github_handler_class, policy_recommender):
        """Test Terraform policy update with PR creation failure"""
        # Mock GitHub handler failure
        mock_github_handler = Mock()
        mock_github_handler.create_pull_request.return_value = {
            "status": "failed",
            "error": "Repository access denied"
        }
        mock_github_handler_class.return_value = mock_github_handler
        
        recommendations = {
            "aws_iam_user.test_user": {
                "recommendation_type": "policy_optimization",
                "resource_name": "test-user",
                "confidence": "high",
                "action_required": "policy_optimization",
                "recommendation_reason": "Test",
                "recommended_policy": {"Version": "2012-10-17", "Statement": []}
            }
        }
        
        result = policy_recommender.update_terraform_policies(recommendations)
        
        assert result == False

    def test_update_terraform_policies_empty(self, policy_recommender):
        """Test Terraform policy update with empty recommendations"""
        result = policy_recommender.update_terraform_policies({})
        assert result == True

    def test_create_minimal_policy(self, policy_recommender):
        """Test creating minimal policy by removing unused actions"""
        current_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "ec2:DescribeInstances"],
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*"
                }
            ]
        }
        
        unused_actions = ["s3:PutObject", "ec2:DescribeInstances"]
        
        minimal_policy = policy_recommender._create_minimal_policy(current_policy, unused_actions)
        
        assert minimal_policy["Version"] == "2012-10-17"
        assert len(minimal_policy["Statement"]) == 2
        
        # First statement should only have s3:GetObject
        allow_statement = minimal_policy["Statement"][0]
        assert allow_statement["Effect"] == "Allow"
        assert allow_statement["Action"] == "s3:GetObject"  # Single action becomes string
        
        # Deny statement should be unchanged
        deny_statement = minimal_policy["Statement"][1]
        assert deny_statement["Effect"] == "Deny"
        assert deny_statement["Action"] == "s3:DeleteObject"


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])