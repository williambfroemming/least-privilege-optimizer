# IAM Analyzer Terraform Module

## Purpose

Analyzes Terraform configurations for IAM resources and deploys a Lambda function for least privilege analysis.

## Usage

```hcl
module "iam_analyzer" {
  source = "./path/to/module"

  tf_path         = "/path/to/terraform/project"
  s3_bucket_name  = "my-unique-bucket-name"
  name_prefix     = "my-project"
  environment     = "dev"

  tags = {
    Project = "Security-Analysis"
    Owner   = "security-team"
  }
}
```
