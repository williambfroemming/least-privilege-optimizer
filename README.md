# Least Privilege Optimizer (Prototype)

This project is a prototype designed to demonstrate how AWS IAM permissions can be automatically analyzed and optimized to follow the principle of least privilege, based on actual usage.

---

## Project Goals

- Understand and visualize the gap between granted vs. used IAM permissions
- Promote security by minimizing unnecessary AWS access
- Automate policy generation and drift detection

---

## Current Functionality

### 1. IAM Policy Sync

A Python script (`iam/scripts/full_sync_iam.py`) connects to the AWS environment and:

- Downloads all IAM **users**, **groups**, and **roles**
- Stores each IAM identity’s **inline** and **attached managed** policies
- Excludes users in the `Administrators` group (to focus on testable targets)
- Saves output to a well-structured folder hierarchy under `/iam/`

### 2. Repository Structure

# least-privilege-optimizer
IAM Folder Strucutre:
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
python3 iam/scripts/full_sync_iam.py
```
