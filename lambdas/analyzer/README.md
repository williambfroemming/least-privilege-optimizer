# IAM Analyzer Lambda Function

This Lambda function serves as an IAM policy analyzer engine. It uses AWS Lambda Powertools for structured logging and error handling.

## Project Structure

```
analyzer/
├── index.py          # Main Lambda handler
├── upload.py         # Deployment script
└── requirements.txt  # Python dependencies
```

## Dependencies

- Python 3.9+
- boto3
- aws-lambda-powertools
- colorlog

## Local Development

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Deployment

The `upload.py` script handles packaging and deploying the Lambda function. It:
- Creates a deployment package with all dependencies
- Bundles the Lambda function code
- Uploads to AWS Lambda

To deploy updates to the Lambda function:

1. Ensure you have AWS credentials configured with appropriate permissions
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
- The Lambda function `iam-analyzer-engine` must already exist in us-east-1

## Logging

The function uses structured logging via AWS Lambda Powertools. Logs can be viewed in CloudWatch Logs after deployment.