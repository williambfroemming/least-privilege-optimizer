# Least Privilege Optimizer

Automate the analysis, optimization, and application of least-privilege IAM policies for AWS users using Terraform and AWS Lambda. This project provides a reusable Terraform module and supporting infrastructure to help you continuously enforce least-privilege access in your AWS environment.

---

## Quick Start

### 1. Clone the Repository

```sh
git clone <your-repo-url>
cd least-privilege-optimizer
```

### 2. Build Lambda Functions (if needed)

```sh
cd infra/terraform/modules/iam-parser/lambda/
./build_all_lambdas.sh
```

### 3. Use the Module in Your Terraform

Below is an example of how to import and configure the `iam-parser` module in your Terraform code:

```hcl
module "iam_analyzer" {
  source  = "../../terraform/modules/iam-parser"
  tf_path = "."

  # Required variables
  environment = "dev"
  github_repo = "williambfroemming/least-privilege-optimizer"

  # Step Function configuration
  create_step_function = true
  enable_daily_schedule = false  # Weekly is better for testing

  # Testing settings
  enable_test_mode      = true
  force_lambda_rebuild  = true
  force_destroy_bucket  = true

  # CloudTrail configuration for testing
  enable_cloudtrail_data_lake   = true
  cloudtrail_retention_days     = 30

  # GitHub token configuration
  github_token_ssm_path = "/github-tokens/iam-analyzer"

  # Automation settings
  schedule_expression = "cron(0 6 ? * SUN *)"  # Weekly on Sundays

  # Lambda configuration
  lambda_timeout     = 300
  lambda_memory_size = 256

  # Storage configuration
  s3_prefix             = "iam-analysis"
  lambda_function_name  = "iam-analyzer"

  # Monitoring
  enable_monitoring  = true
  log_retention_days = 7

  # Tags
  tags = {
    Project     = "IAM-Analyzer"
    ManagedBy   = "Terraform"
    Environment = "dev"
    Owner       = "ScopeDown Team"
    Purpose     = "Automated IAM least privilege analysis"
    Testing     = "true"
  }
}
```

---

## Project Structure

```
infra/
  terraform/                # Main Terraform root
    modules/
      iam-parser/           # The reusable IAM analysis module
        lambda/             # Lambda source code and build scripts
        ...
    ...
  sample-iac-app/           # Example app and frontend
```

---

## Module Inputs & Outputs

> **Note:** Please refer to `infra/terraform/modules/iam-parser/variables.tf` and `outputs.tf` for the full list. (You can also run `terraform-docs` for auto-generated documentation.)

### Inputs

- `environment` (string): Deployment environment (e.g., dev, prod)
- `github_repo` (string): GitHub repository for PR automation
- ... _(add more as needed)_

### Outputs

- _(List outputs here)_

---

## Development & Contribution

- Fork and clone the repo
- Build Lambda zips with `./build_all_lambdas.sh` before deploying
- Open issues or PRs for bugs, features, or questions

---

## License

MIT

---

## Contributors

- Aish Joshi
- David Kocen
- Matt Neith
