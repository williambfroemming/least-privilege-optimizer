# Test file to verify Alice policy detection and comment cleaning fixes
import pytest
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from modules.policy_recommender import PolicyRecommender

class TestAlicePolicyFixes:
    """Test that our fixes properly handle Alice's policy and comment cleaning"""
    
    def test_alice_policy_detection(self):
        """Test that Alice's policy is properly detected in the real policies.tf content"""
        # Real content from policies.tf (without inline comments that might be from main branch)
        real_policies_content = '''resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "OverlyPermissiveReadAndWrite",
        Effect   = "Allow",
        Action   = [
          "s3:*",
          "athena:*",
          "glue:*",
          "cloudwatch:Get*",
          "cloudwatch:PutMetricData",
          "dynamodb:Scan",
          "kms:Decrypt",
          "iam:List*",
          "iam:Get*",
          "lambda:InvokeFunction",
          "sts:AssumeRole"
        ],
        Resource = "*"
      }
    ]
  })
}'''
        
        # Mock PolicyRecommender
        recommender = PolicyRecommender.__new__(PolicyRecommender)
        
        # Test various Alice-related resource keys
        test_cases = [
            ("alice_analyst_test", "aws_iam_user.alice_analyst_test"),
            ("alice_analyst_policy", "aws_iam_user_policy.alice_analyst_policy"),
        ]
        
        for resource_name, resource_key in test_cases:
            result = recommender._resource_exists_in_file(
                real_policies_content, 
                resource_name, 
                resource_key
            )
            assert result == True, f"Failed to detect Alice's policy with resource_name={resource_name}, resource_key={resource_key}"
            print(f"✅ Successfully detected Alice's policy with pattern: {resource_key}")
    
    def test_comment_cleaning_functionality(self):
        """Test that inline comments are properly removed to prevent branch mixing"""
        # Content with inline comments that might be from main branch
        content_with_comments = '''resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "OverlyPermissiveReadAndWrite",
        Effect   = "Allow",
        Action   = [
          "s3:*",                         # Full S3 access
          "athena:*",                     # All Athena actions
          "glue:*",                       # All Glue actions (overkill for most analysts)
          "cloudwatch:Get*",              # OK
          "cloudwatch:PutMetricData",     # Write perms analysts shouldn't need
          "dynamodb:Scan",                # Too broad for sensitive data
          "kms:Decrypt",                  # Dangerous without restrictions
          "iam:List*",                    # Allows recon
          "iam:Get*",                     # More recon
          "lambda:InvokeFunction",        # Could be misused
          "sts:AssumeRole"                # Very risky unless scoped tightly
        ],
        Resource = "*"
      }
    ]
  })
}'''
        
        recommender = PolicyRecommender.__new__(PolicyRecommender)
        
        # Test comment cleaning
        cleaned_content = recommender._clean_inline_comments(content_with_comments)
        
        # Verify inline comments are removed
        assert "# Full S3 access" not in cleaned_content
        assert "# All Athena actions" not in cleaned_content
        assert "# overkill for most analysts" not in cleaned_content
        assert "# Dangerous without restrictions" not in cleaned_content
        assert "# Very risky unless scoped tightly" not in cleaned_content
        
        # Verify the actual code structure is preserved
        assert '"s3:*",' in cleaned_content
        assert '"athena:*",' in cleaned_content
        assert '"glue:*",' in cleaned_content
        
        print("✅ Successfully cleaned inline comments while preserving code structure")
    
    def test_structural_comment_preservation(self):
        """Test that structural comments are preserved while descriptive ones are removed"""
        content_with_mixed_comments = '''# MODIFIED BY LEAST PRIVILEGE OPTIMIZER - 2025-06-22
# Finding ID: test-finding-123
# Based on AWS Access Analyzer findings

resource "aws_iam_user_policy" "test_policy" {
  name = "test-policy"
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "s3:*",                    # Too much access
          "lambda:*"                 # Excessive permissions
        ],
        Resource = "*"
      }
    ]
  })
}'''
        
        recommender = PolicyRecommender.__new__(PolicyRecommender)
        cleaned_content = recommender._clean_inline_comments(content_with_mixed_comments)
        
        # Verify structural comments are preserved
        assert "# MODIFIED BY LEAST PRIVILEGE OPTIMIZER" in cleaned_content
        assert "# Finding ID: test-finding-123" in cleaned_content
        assert "# Based on AWS Access Analyzer findings" in cleaned_content
        
        # Verify descriptive inline comments are removed
        assert "# Too much access" not in cleaned_content
        assert "# Excessive permissions" not in cleaned_content
        
        print("✅ Successfully preserved structural comments while removing descriptive ones")

if __name__ == "__main__":
    test = TestAlicePolicyFixes()
    test.test_alice_policy_detection()
    test.test_comment_cleaning_functionality()
    test.test_structural_comment_preservation()
    print("🎉 All Alice policy fix tests passed!")