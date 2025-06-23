# Real AWS Integration Testing for IAM Analyzer Lambda

This directory contains comprehensive integration tests that run your IAM Analyzer Lambda function locally against real AWS resources and show you exactly what would be created in GitHub PRs.

## 🚀 Quick Start

1. **Set up your environment:**
   ```bash
   # Copy the environment template
   cp .env.example .env
   
   # Edit .env with your real AWS credentials and configuration
   nano .env  # or use your preferred editor
   ```

2. **Install dependencies:**
   ```bash
   pip install -r src/requirements.txt
   pip install python-dotenv  # For loading .env files
   ```

3. **Run the tests:**
   ```bash
   # Dry run mode (no real GitHub changes)
   python run_integration_tests.py
   
   # Or run individual test components
   python run_integration_tests.py --test connectivity
   python run_integration_tests.py --test workflow
   ```

## 📋 Required Configuration

Edit your `.env` file with these required values:

### AWS Configuration
```bash
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
```

### IAM Access Analyzer
```bash
ANALYZER_ARN=arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/your-analyzer-name
```

### S3 Bucket (where your IAM resources are stored)
```bash
S3_BUCKET=your-iam-resources-bucket
S3_PREFIX=iam-resources
```

### GitHub Repository
```bash
GITHUB_TOKEN=ghp_your_github_personal_access_token
GITHUB_REPO=your-github-username/your-repo-name
```

### Optional Test Configuration
```bash
# Filter to specific resources (comma-separated)
TEST_RESOURCE_FILTER=data-engineer,support-analyst,admin-role

# Control PR creation
CREATE_REAL_PR=false  # Set to true to actually create GitHub PRs
DRY_RUN=true         # Set to false to make real changes
```

## 🧪 Available Tests

### 1. AWS Connectivity Test
Tests connection to your AWS services:
```bash
python run_integration_tests.py --test connectivity
```
- Verifies Access Analyzer connection
- Lists available analyzers
- Confirms target analyzer exists
- Tests S3 bucket access
- Checks for IAM resources file

### 2. Resource Fetching Test
Tests fetching real IAM resources from S3:
```bash
python run_integration_tests.py --test resources
```
- Fetches all IAM resources from your S3 bucket
- Shows breakdown by resource type (users, roles, groups, policies)
- Applies resource filtering if configured
- Displays resource details

### 3. Access Analyzer Findings Test
Tests fetching real findings from Access Analyzer:
```bash
python run_integration_tests.py --test findings
```
- Gets findings for your IAM resources
- Shows finding statistics by type and status
- Displays detailed finding information
- Tests finding structure parsing

### 4. Complete Lambda Workflow Test
Runs the entire lambda function locally:
```bash
python run_integration_tests.py --test workflow
```
- Executes the complete lambda handler
- Shows all processing steps
- Displays policy recommendations
- **Shows exact content that would be in GitHub PRs**
- Runs in safe dry-run mode by default

### 5. Policy Output Format Test
Shows detailed policy recommendation formatting:
```bash
python run_integration_tests.py --test policy-format
```
- Processes Access Analyzer findings
- Generates policy recommendations
- Shows Terraform files that would be created
- Displays JSON policy files
- Shows PR file structure and content

## 📝 What You'll See

The tests will show you:

### AWS Resources Analysis
```
✅ Fetched 15 IAM resources from S3

Resource breakdown:
  AWS::IAM::User: 8 resources
    - data-engineer (arn:aws:iam::123456789012:user/data-engineer)
    - support-analyst (arn:aws:iam::123456789012:user/support-analyst)
    - admin-user (arn:aws:iam::123456789012:user/admin-user)
    ... and 5 more

  AWS::IAM::Role: 5 resources
    - admin-role (arn:aws:iam::123456789012:role/admin-role)
    - lambda-execution-role (arn:aws:iam::123456789012:role/lambda-execution-role)
    ... and 3 more
```

### Access Analyzer Findings
```
✅ Found 12 Access Analyzer findings
   Summary: 12 total findings
   By type: {'UNUSED_ACCESS': 8, 'EXTERNAL_ACCESS': 3, 'UNUSED_IAM_ROLE': 1}
   By status: {'ACTIVE': 11, 'ARCHIVED': 1}

Detailed findings:
  1. UNUSED_ACCESS - ACTIVE
     Resource: arn:aws:iam::123456789012:user/data-engineer
     ID: finding-abc123
     Created: 2025-06-21T10:30:00Z
```

### Policy Recommendations
```
📝 Generated 5 policy recommendations:

🔍 Resource: aws_iam_user.data-engineer
   Type: policy_optimization
   Confidence: high
   Action Required: policy_optimization
   Unused Actions: 15
     - ec2:TerminateInstances
     - rds:DeleteDBInstance
     - s3:DeleteBucket
     ... and 12 more
   Recommended Policy: 3 statements
     Example: Allow ['s3:GetObject', 's3:ListBucket'] on arn:aws:s3:::data-bucket/*
```

### GitHub PR Content Preview
```
📁 Files that would be created in GitHub PR:

--- terraform/policies/least_privilege_data_engineer.tf ---
# Generated by IAM Access Analyzer - Least Privilege Policy
# Resource: aws_iam_user.data-engineer
# Finding ID: finding-abc123
# Generated: 2025-06-22T14:30:00Z

resource "aws_iam_policy" "least_privilege_data_engineer" {
  name        = "LeastPrivilegeDataEngineer"
  description = "Least privilege policy for data-engineer based on Access Analyzer findings"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:PutObject"
        ]
        Resource = [
          "arn:aws:s3:::data-bucket/*",
          "arn:aws:s3:::data-bucket"
        ]
      }
    ]
  })

  tags = {
    CreatedBy = "LeastPrivilegeOptimizer"
    Purpose   = "AccessAnalyzerRecommendation"
    Resource  = "data-engineer"
  }
}

# Attach the least privilege policy to the user
resource "aws_iam_user_policy_attachment" "data_engineer_least_privilege" {
  user       = aws_iam_user.data_engineer.name
  policy_arn = aws_iam_policy.least_privilege_data_engineer.arn
}

--- policies/generated/least_privilege_data_engineer.json ---
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::data-bucket/*",
        "arn:aws:s3:::data-bucket"
      ]
    }
  ]
}
```

## 🔴 Creating Real GitHub PRs

**⚠️ WARNING:** Only use this after you've verified the dry-run output!

To create actual GitHub PRs:
```bash
# This will create REAL pull requests in your repository
python run_integration_tests.py --live-pr
```

This will:
1. Ask for confirmation before proceeding
2. Create a new branch with timestamp
3. Commit all the generated files
4. Create a pull request with policy recommendations
5. Show you the PR URL

## 🔧 Advanced Usage

### Filter to Specific Resources
```bash
# Only analyze specific resources
export TEST_RESOURCE_FILTER="data-engineer,support-analyst"
python run_integration_tests.py
```

### Custom Branch Names
```bash
# Use custom branch prefix
export HEAD_BRANCH_PREFIX="iam-fixes"
python run_integration_tests.py --live-pr
```

### Debug Mode
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python run_integration_tests.py
```

## 📊 Understanding the Output

### Recommendation Types
- **`policy_optimization`**: Remove unused permissions from existing policies
- **`least_privilege_suggestion`**: Create new least-privilege policies
- **`security_review`**: Manual review required for security findings
- **`removal_candidate`**: Unused resources that could be removed

### Confidence Levels
- **`high`**: Strong evidence from Access Analyzer findings
- **`medium`**: Some evidence but may need manual review
- **`low`**: Minimal evidence, exercise caution

### Action Required
- **`policy_optimization`**: Automated policy updates recommended
- **`manual_review`**: Human review required before changes
- **`review_for_removal`**: Consider removing unused resources

## 🛠️ Troubleshooting

### Common Issues

**"No .env file found"**
```bash
cp .env.example .env
# Edit .env with your configuration
```

**"Missing required environment variables"**
- Check that all required variables in `.env` are set
- Verify AWS credentials are valid
- Ensure Access Analyzer ARN is correct

**"Target analyzer not found"**
- Verify the ANALYZER_ARN in your .env file
- Ensure the analyzer exists in the specified AWS region
- Check AWS permissions for Access Analyzer

**"Resources file not found"**
- Verify S3_BUCKET and S3_PREFIX are correct
- Ensure the `latest.json` file exists in your S3 bucket
- Check AWS permissions for S3 access

**"No findings available"**
- Run Access Analyzer scans in AWS console first
- Wait for findings to be generated (can take time)
- Check that your IAM resources have actual usage to analyze

### Debug Steps
1. Run connectivity test first: `python run_integration_tests.py --test connectivity`
2. Check individual components: `--test resources`, `--test findings`
3. Enable debug logging: `export LOG_LEVEL=DEBUG`
4. Review AWS CloudTrail logs for API call issues

## 🎯 Next Steps

After running the tests:

1. **Review the recommendations** - Make sure they make sense for your environment
2. **Test in a development environment** - Apply changes to dev/staging first  
3. **Create real PRs** - Use `--live-pr` when you're ready
4. **Review PRs carefully** - Don't merge automatically, review the changes
5. **Monitor after deployment** - Ensure applications still work with new policies

The goal is to gradually move toward least-privilege IAM policies based on actual usage patterns detected by Access Analyzer.