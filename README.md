# Least Privilege Optimizer (Prototype)

This project is a prototype designed to demonstrate how AWS IAM permissions can be automatically analyzed and optimized to follow the principle of least privilege, based on actual usage.

---

## Project Goals

- Understand and visualize the gap between granted vs. used IAM permissions
- Promote security by minimizing unnecessary AWS access
- Automate policy generation and drift detection

---

## Current Functionality

### 1. Infrastructure-as-Code (IaC)

The entire AWS environment is now managed using **Terraform**, including:

- S3 buckets (CloudTrail logs, Athena query results, application data)
- IAM users, roles, groups, and policies
- GitHub Actions OIDC identity provider
- Lambda function and execution role
- CloudTrail configuration (except advanced selectors, which are managed manually)

Terraform remote state is securely stored in an encrypted S3 bucket, with state locking via DynamoDB. This ensures reproducibility, consistency, and safe team collaboration.

---

### 2. IAM Policy Sync (Legacy + Analysis Tooling)

The Python script `iam/scripts/full_sync_iam.py` connects to the AWS environment and:

- Downloads all IAM **users**, **groups**, and **roles**
- Retrieves each identity’s **inline** and **attached managed** policies
- Excludes users in the `Administrators` group to avoid modifying real accounts
- Saves IAM artifacts to a structured, Git-tracked hierarchy under `/iam/`

This supports policy analysis, auditing, and eventual policy optimization.

---

### 2. Simulated Role Activity

To support least privilege analysis based on actual usage, this project includes a set of scripts under `scripts/` that simulate AWS activity for different IAM roles. These scripts assume their respective roles and perform relevant AWS operations that generate CloudTrail events for analysis.

### Prerequisites

- AWS CLI installed and authenticated as an identity allowed to assume the test roles
- `jq` installed (`brew install jq` on macOS, or `sudo apt install jq` on Debian/Ubuntu)
- Pre-created test infrastructure:
  - `ucb-capstone-bucket` for S3 operations
  - `ucb-capstone-athena-results` for Athena query output
  - A Glue catalog with at least one database and table (e.g., `sampledb.elb_logs`)
  - A log group such as `/aws/lambda/your-lambda` for CloudWatch testing (optional)

---

### `simulate_test_data_engineer.sh`

Simulates activity by the `test-data-engineer` role:

- Uploads and deletes a file (`test.csv`) in `ucb-capstone-bucket`
- Runs an Athena query (output to `s3://ucb-capstone-athena-results/athena-results/`)
- Queries the Glue Data Catalog
- Describes CloudWatch log groups
- Describes EC2 instances

**Usage:**

```bash
cd scripts
chmod +x simulate_test_data_engineer.sh
./simulate_test_data_engineer.sh
```
