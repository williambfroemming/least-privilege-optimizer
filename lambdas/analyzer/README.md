# IAM Analyzer Lambda Function

This Lambda function serves as an IAM policy analyzer engine that automatically analyzes IAM policies using AWS IAM Access Analyzer and proposes least-privilege optimizations through GitHub pull requests.

## Project Structure

```
analyzer/
├── index.py             # Main Lambda handler
├── upload.py           # Deployment script
├── requirements.txt    # Python dependencies
├── modules/           # Core functionality modules
│   ├── __init__.py
│   ├── iam_analyzer.py  # IAM Access Analyzer wrapper
│   └── github_pr.py     # GitHub pull request handler
└── test/              # Test files
    ├── conftest.py    # Pytest configuration
    └── test_integration.py  # Integration tests
```

## Components

### IAM Analyzer (iam_analyzer.py)
Wrapper class for AWS IAM Access Analyzer operations:
- Lists findings from Access Analyzer
- Generates policy recommendations
- Validates IAM policies
- Manages analyzer findings

### GitHub PR Handler (github_pr.py)
Handles all GitHub operations:
- Creates/updates branches
- Manages policy file changes
- Creates/updates pull requests with policy recommendations

### Main Handler (index.py)
The Lambda entry point that:
- Validates environment configuration
- Processes Access Analyzer findings
- Coordinates policy generation and PR creation
- Handles error cases and logging

## Configuration

### Environment Variables
Required environment variables:
```
GITHUB_TOKEN=your_github_personal_access_token
GITHUB_REPO=owner/repository
AWS_REGION=us-east-1
```

Copy `.env.example` to `.env` for local development:
```bash
cp .env.example .env
```

## Integration Testing

The project includes comprehensive integration tests that verify:
- IAM Access Analyzer operations
- GitHub PR creation
- Full end-to-end policy analysis and PR workflow

To run the integration tests:

1. Set up your environment:
```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
pip install -r requirements.txt
```

2. Configure test environment:
- Copy `.env.example` to `.env`
- Fill in required credentials and configuration
- Ensure you have an AWS Access Analyzer set up

3. Run the tests:
```bash
python -m pytest test/test_integration.py -v
```

## Deployment

The `upload.py` script handles packaging and deploying the Lambda function:

1. Ensure AWS credentials are configured with permissions for Lambda updates

2. Run the deployment script:
```bash
python upload.py
```

The script will:
- Install dependencies to a temporary directory
- Create a ZIP package with all required files
- Upload to the `iam-analyzer-engine` Lambda function
- Clean up temporary files

### Prerequisites for Deployment

- AWS CLI configured with appropriate credentials
- Permissions to update Lambda functions
- The Lambda function `iam-analyzer-engine` must exist in us-east-1
- GitHub Personal Access Token with repo permissions
- AWS IAM Access Analyzer configured in target account

## Logging and Monitoring

The function uses AWS Lambda Powertools for structured logging with the following features:
- JSON-formatted logs with request context
- Automatic correlation IDs
- Error tracking and stack traces
- CloudWatch integration

View logs in CloudWatch Logs under the `/aws/lambda/iam-analyzer-engine` log group.

## Lambda Invocation

The Lambda expects events in the following format:
```json
{
    "analyzer_arn": "arn:aws:access-analyzer:region:account:analyzer/name",
    "pr_title": "Update IAM policies based on analysis",
    "pr_body": "Automated PR for IAM policy updates",
    "base_branch": "main",  // optional
    "head_branch": "iam-updates"  // optional
}
```

## Error Handling

The Lambda implements comprehensive error handling:
- Environment validation
- AWS API error handling
- GitHub API error recovery
- Structured error responses

Error responses follow the format:
```json
{
    "statusCode": 500,
    "body": {
        "error": "Error message",
        "status": "failed"
    }
}
```