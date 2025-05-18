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

## Repository Structure

```bash
iam/
├── users/             # Metadata for test IAM users
├── policies/
│   ├── aws-managed/   # AWS-managed policy snapshots
│   └── inline/        # Custom inline policies per user/role/group
├── groups/            # IAM group definitions
├── roles/             # IAM role definitions and trust policies
└── scripts/
    └── full_sync_iam.py  # Main sync script
```

## How to Sync AWS and Repository

Log into AWS CLI, then run:

```bash
python3 iam/scripts/sync_iam_to_repo.py
```
