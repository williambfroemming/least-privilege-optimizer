# IAM Analyzer Terraform Module

A Terraform module that analyzes IAM configurations in your Terraform projects to help identify potential security issues and implement least-privilege access patterns. The module provides both static analysis capabilities and optional Lambda-based processing with comprehensive S3 storage and monitoring.

## Features

- **IAM Policy Analysis**: Parses and analyzes IAM policies, roles, and permissions from Terraform configurations
- **Least Privilege Recommendations**: Identifies overly permissive policies and suggests improvements
- **S3 Storage**: Secure, encrypted storage for analysis outputs with lifecycle management
- **Optional Lambda Processing**: Server-side analysis engine with CloudWatch monitoring
- **Security Best Practices**: KMS encryption, access logging, and SNS notifications
- **Multi-Environment Support**: Configurable for dev, staging, and production environments

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Terraform     │───▶│  IAM Analyzer    │───▶│   S3 Bucket     │
│  Configuration  │    │     Module       │    │   (Encrypted)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │                         │
                              ▼                         ▼
                       ┌──────────────┐         ┌──────────────┐
                       │   Lambda     │         │    SNS       │
                       │  (Optional)  │         │ Notifications│
                       └──────────────┘         └──────────────┘
```

## Quick Start

### Basic Usage (S3 Only)

```hcl
module "iam_analyzer" {
  source = "./path/to/iam-analyzer-module"

  tf_path     = "/path/to/your/terraform/project"
  environment = "dev"

  tags = {
    Project = "MyProject"
    Owner   = "SecurityTeam"
  }
}
```

### Full Usage (with Lambda)

```hcl
module "iam_analyzer" {
  source = "./path/to/iam-analyzer-module"

  # Required
  tf_path = "/path/to/your/terraform/project"

  # S3 Configuration
  s3_bucket_name = "my-iam-analysis-bucket"
  s3_prefix      = "security-analysis"

  # Lambda Configuration
  create_lambda        = true
  lambda_function_name = "iam-security-analyzer"
  lambda_timeout       = 30
  lambda_memory_size   = 256

  # Environment and Tagging
  environment = "prod"
  name_prefix = "myorg-security"

  # Monitoring
  enable_monitoring    = true
  log_retention_days   = 30

  tags = {
    Project     = "SecurityAnalysis"
    Owner       = "SecurityTeam"
    Environment = "production"
    Compliance  = "SOC2"
  }
}
```

## Requirements

| Name      | Version |
| --------- | ------- |
| terraform | >= 1.0  |
| aws       | ~> 5.0  |
| random    | ~> 3.1  |
| null      | ~> 3.1  |

## Providers

| Name   | Version |
| ------ | ------- |
| aws    | ~> 5.0  |
| random | ~> 3.1  |
| null   | ~> 3.1  |

## Resources Created

### Core Resources

- **S3 Bucket**: Encrypted storage for analysis outputs
- **KMS Key**: Customer-managed encryption key
- **IAM Roles & Policies**: Least-privilege access for Lambda
- **SNS Topic**: Security event notifications

### Optional Resources (when `create_lambda = true`)

- **Lambda Function**: Analysis engine
- **Lambda Layer**: Python dependencies
- **CloudWatch Log Group**: Function logs
- **CloudWatch Alarms**: Error monitoring

### Supporting Resources

- **S3 Access Logs Bucket**: Audit trail for S3 access
- **Lifecycle Policies**: Automated cleanup and cost optimization
- **Bucket Notifications**: Real-time security alerts

## Inputs

| Name                 | Description                                            | Type          | Default                                                 | Required |
| -------------------- | ------------------------------------------------------ | ------------- | ------------------------------------------------------- | :------: |
| tf_path              | Path to the Terraform project to be analyzed           | `string`      | n/a                                                     |   yes    |
| s3_bucket_name       | S3 bucket name for output (auto-generated if null)     | `string`      | `null`                                                  |    no    |
| s3_prefix            | Prefix inside the S3 bucket where files will be stored | `string`      | `"iam-parsed"`                                          |    no    |
| create_lambda        | Whether to create the Lambda function                  | `bool`        | `true`                                                  |    no    |
| lambda_function_name | Name for the Lambda function (will be prefixed)        | `string`      | `"iam-analyzer-engine"`                                 |    no    |
| lambda_timeout       | Timeout for the Lambda function (seconds)              | `number`      | `10`                                                    |    no    |
| lambda_memory_size   | Memory allocation for Lambda function (MB)             | `number`      | `128`                                                   |    no    |
| log_retention_days   | CloudWatch log retention period (days)                 | `number`      | `7`                                                     |    no    |
| name_prefix          | Prefix for resource names (auto-generated if empty)    | `string`      | `""`                                                    |    no    |
| environment          | Environment name (dev, staging, prod)                  | `string`      | `"dev"`                                                 |    no    |
| tags                 | Tags to apply to all resources                         | `map(string)` | `{"Project": "IAM-Analyzer", "ManagedBy": "Terraform"}` |    no    |
| enable_monitoring    | Enable CloudWatch monitoring and alarms                | `bool`        | `true`                                                  |    no    |
| force_destroy_bucket | Allow bucket to be destroyed with objects (testing)    | `bool`        | `false`                                                 |    no    |
| python_runtime       | Python runtime version for Lambda                      | `string`      | `"python3.9"`                                           |    no    |
| force_lambda_rebuild | Force Lambda function rebuild (development)            | `bool`        | `false`                                                 |    no    |

## Outputs

| Name                  | Description                                            |
| --------------------- | ------------------------------------------------------ |
| s3_bucket_name        | Name of the S3 bucket created for IAM analysis outputs |
| s3_bucket_arn         | ARN of the S3 bucket                                   |
| s3_bucket_domain_name | Domain name of the S3 bucket                           |
| s3_prefix             | S3 prefix for storing analysis outputs                 |
| latest_output_key     | S3 key for the latest analysis output                  |
| lambda_function_arn   | ARN of the IAM Analyzer Lambda function (if created)   |
| lambda_function_name  | Name of the IAM Analyzer Lambda function (if created)  |
| lambda_role_arn       | ARN of the Lambda execution role (if created)          |
| name_prefix           | Generated name prefix used for resources               |
| aws_region            | AWS region where resources are deployed                |
| aws_account_id        | AWS account ID where resources are deployed            |

## Security Features

### Encryption

- **S3 Server-Side Encryption**: All objects encrypted with customer-managed KMS keys
- **KMS Key Rotation**: Automatic annual key rotation enabled
- **Encryption in Transit**: All API calls use HTTPS/TLS

### Access Control

- **Least Privilege IAM**: Minimal permissions for Lambda execution
- **S3 Bucket Policies**: Restrictive access based on prefixes
- **Public Access Blocked**: All S3 public access explicitly denied

### Monitoring & Auditing

- **Access Logging**: Comprehensive S3 access logs
- **CloudWatch Monitoring**: Lambda error rates and performance metrics
- **SNS Notifications**: Real-time alerts for security events
- **Versioning**: S3 object versioning for audit trails

### Compliance

- **Resource Tagging**: Consistent tagging for governance
- **Lifecycle Management**: Automated data retention policies
- **Multi-Part Upload Cleanup**: Prevents incomplete upload accumulation

## Usage Examples

### Development Environment

```hcl
module "iam_analyzer_dev" {
  source = "./iam-analyzer"

  tf_path     = "./terraform/dev"
  environment = "dev"

  # Minimal setup for development
  create_lambda         = false
  enable_monitoring     = false
  log_retention_days    = 3
  force_destroy_bucket  = true

  tags = {
    Environment = "development"
    Purpose     = "security-testing"
  }
}
```

### Production Environment

```hcl
module "iam_analyzer_prod" {
  source = "./iam-analyzer"

  tf_path = "./terraform/production"

  # Production-grade configuration
  environment           = "prod"
  create_lambda         = true
  lambda_memory_size    = 512
  lambda_timeout        = 60
  log_retention_days    = 365
  enable_monitoring     = true

  # Enhanced security
  s3_prefix = "security/iam-analysis"

  tags = {
    Environment   = "production"
    Compliance    = "SOC2"
    DataClass     = "confidential"
    BackupPolicy  = "required"
  }
}
```

### Multi-Project Analysis

```hcl
# Analyze multiple Terraform projects
module "iam_analyzer_frontend" {
  source = "./iam-analyzer"

  tf_path     = "./projects/frontend"
  name_prefix = "frontend-security"
  s3_prefix   = "analysis/frontend"

  tags = {
    Project = "Frontend"
    Team    = "WebTeam"
  }
}

module "iam_analyzer_backend" {
  source = "./iam-analyzer"

  tf_path     = "./projects/backend"
  name_prefix = "backend-security"
  s3_prefix   = "analysis/backend"

  tags = {
    Project = "Backend"
    Team    = "ApiTeam"
  }
}
```

## Prerequisites

1. **AWS CLI configured** with appropriate permissions
2. **Python 3.8+** installed (for Lambda build process)
3. **Terraform** >= 1.0
4. **Required IAM permissions**:
   - S3: CreateBucket, PutObject, GetObject, PutBucketPolicy
   - IAM: CreateRole, AttachRolePolicy, CreatePolicy
   - Lambda: CreateFunction, UpdateFunctionCode (if using Lambda)
   - KMS: CreateKey, CreateAlias
   - CloudWatch: CreateLogGroup, PutMetricAlarm
   - SNS: CreateTopic, SetTopicAttributes

## Development

### Local Testing

```bash
# Test without Lambda
terraform plan -var="create_lambda=false" -var="tf_path=./test-configs"

# Test with forced rebuild
terraform apply -var="force_lambda_rebuild=true"
```

### Lambda Development

The Lambda function source code should be placed in the `lambda/` directory:

```
lambda/
├── build_lambda.sh      # Build script
├── index.py            # Main Lambda handler
├── requirements.txt    # Python dependencies
└── lib/               # Additional modules
```

## Troubleshooting

### Common Issues

1. **S3 Bucket Name Conflicts**
   - Solution: Leave `s3_bucket_name` as `null` for auto-generation
2. **Lambda Build Failures**
   - Ensure `lambda/build_lambda.sh` is executable
   - Check Python dependencies in `requirements.txt`
3. **Permission Errors**
   - Verify AWS credentials have required permissions
   - Check IAM policy attachments

### Debug Mode

```hcl
module "iam_analyzer" {
  source = "./iam-analyzer"

  tf_path = "./test"

  # Debug settings
  environment         = "dev"
  log_retention_days  = 1
  enable_monitoring   = true

  tags = {
    Debug = "true"
  }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This module is licensed under the MIT License. See LICENSE file for details.

## Support

For issues and questions:

- Create an issue in the repository
- Review the troubleshooting section
- Check AWS CloudWatch logs for Lambda issues

## Changelog

### v1.0.0

- Initial release
- S3 storage with KMS encryption
- Optional Lambda processing
- CloudWatch monitoring
- SNS notifications
- Multi-environment support
