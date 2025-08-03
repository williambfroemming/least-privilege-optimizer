# ScopeDown: Intelligent Identity and Access Management (IAM) Least Privilege Automation

**UC Berkeley MICS Capstone Project 2025**

ScopeDown is an intelligent automation system that continuously enforces least privilege principles in cloud IAM—not just once, but as an ongoing security practice. Built as a comprehensive Terraform module with serverless architecture, ScopeDown automatically generates optimized IAM policy code changes and submits them as pull requests, integrating seamlessly into existing CI/CD pipelines and Infrastructure as Code workflows. The scope of our project focused on users with AWS managed and inline policies attached to their attached to their IAM user identities, specifically analyzing permissions usage to recommend policy reductions based on actual activity captured in AWS CloudTrail.

## 🎯 The Business Problem

In today's cloud-first world, IAM permissions are the keys to the kingdom. Yet organizations struggle with a critical security paradox:

- **Most cloud IAM permissions go unused**, creating a massive attack surface
- Security teams spend countless hours manually auditing permissions
- Developers need quick access, leading to over-permissioned roles
- Compliance audits reveal excessive privileges across production environments
- When breaches occur, the blast radius is unnecessarily large

**The result?** Organizations are caught between security requirements and operational velocity, often choosing convenience over least privilege principles.

## 💡 The ScopeDown Solution

### What Makes ScopeDown Different

ScopeDown transforms IAM security from a reactive, manual process into a proactive, automated practice:

#### **1. Continuous Monitoring & Analysis**
- **CloudTrail Lake Integration**: Analyzes real API usage patterns across your cloud environment
- **Real-time Permission Tracking**: Understands what permissions are actually used vs. what's granted
- **Usage Pattern Analysis**: Identifies unused permissions with data-driven insights

#### **2. Infrastructure as Code Native**
- **Multi-Cloud Ready**: Currently supports AWS with extensible architecture for other cloud providers
- **Terraform Integration**: Works directly with your existing Terraform configurations
- **GitHub Automation**: Creates pull requests with optimized policies automatically
- **Zero Disruption**: Preserves your existing workflows and CI/CD pipelines

#### **3. Event-Driven Automation**
- **Serverless Architecture**: Event-driven Lambda functions that scale automatically
- **Smart Recommendations**: Conservative approach that maintains access when usage is unclear
- **Automated Code Generation**: Produces actual Terraform code changes for review

#### **4. Developer-Friendly Experience**
- **Meets You Where You Are**: Works with your existing Terraform and GitHub workflows
- **Human-in-the-Loop**: Makes code changes only through pull requests for mandatory review
- **Clear Audit Trails**: Every change is documented and reviewable

---

## 🏗️ Architecture Overview

ScopeDown employs a serverless architecture designed for scalability:

### **Multi-Stage Processing Pipeline**

```
Terraform Files → S3 Analysis Store → IAM Data Extraction → CloudTrail Query → 
Usage Analysis → Policy Optimization → GitHub PR Creation → Review & Merge
```

### **Core Components**

#### **🔍 Step 1: IAM Data Extraction (`read-s3`)**
- Parses Terraform configurations to identify IAM resources
- Extracts user/role definitions and associated policies
- Creates comprehensive IAM inventory with source file mapping

#### **📊 Step 2-3: CloudTrail Analysis (`start-cloudtrail`, `check-cloudtrail`)**
- Launches CloudTrail Lake queries to analyze API usage patterns
- Handles batch processing for large user bases
- Aggregates usage statistics across configurable time periods

#### **📁 Step 4: GitHub Integration (`fetch-terraform`)**
- Clones repository and fetches current Terraform configurations
- Maps policies to source files for accurate modification targeting
- Preserves existing code structure and formatting

#### **🧠 Step 5: Policy Intelligence (`parse-policies`)**
- Compares granted permissions against actual API usage
- Generates least-privilege recommendations
- Creates modification plans with detailed change descriptions

#### **✏️ Step 6: Safe Modifications (`apply-modifications`)**
- Applies policy optimizations with conservative safety checks
- Preserves access when usage patterns are unclear
- Maintains Terraform formatting and structure

#### **🔄 Step 7: Automated PRs (`github-pr`)**
- Creates detailed pull requests with modification summaries
- Includes security impact analysis and recommendations
- Provides clear audit trails for compliance requirements

### **Supporting Infrastructure**

- **CloudTrail Lake**: Direct SQL querying for fast API usage analysis
- **S3 Storage**: Encrypted storage for analysis results and configurations
- **CloudWatch**: Comprehensive monitoring and alerting
- **AWS Systems Manager**: Secure token and configuration management
- **EventBridge**: Automated scheduling for continuous monitoring

---

## � Business Impact & Benefits

### **Immediate Security Improvements**

- **Reduced Attack Surface**: Eliminate unused permissions across your environment
- **Faster Incident Response**: Limited blast radius when credentials are compromised
- **Compliance Readiness**: Automated documentation and audit trails for security reviews

### **Operational Excellence**

- **Developer Velocity**: Maintain speed while improving security posture
- **Reduced Manual Work**: Eliminate hours of manual permission auditing
- **Consistent Enforcement**: Apply least privilege principles uniformly across teams

### **Cost Optimization**

- **Reduced CloudTrail Costs**: Efficient querying strategies minimize data processing fees
- **Serverless Economics**: Pay only for analysis runs, not idle infrastructure
- **Resource Efficiency**: Optimized Lambda functions with intelligent memory allocation

### **Risk Mitigation**

- **Proactive Security**: Identify and remediate permission creep before it becomes a problem
- **Change Management**: Every permission change is documented and reviewable
- **Human-in-the-Loop**: All changes require pull request approval for safety

---

## �🚀 Quick Start Guide

### Prerequisites

- AWS CLI configured with appropriate permissions
- Terraform >= 1.0
- GitHub repository with admin access
- AWS Access Analyzer enabled in your account

### 1. Clone and Setup

```bash
git clone https://github.com/your-org/least-privilege-optimizer
cd least-privilege-optimizer
```

### 2. Build Lambda Functions

```bash
cd infra/terraform/modules/iam-parser/lambda/
chmod +x build_all_lambdas.sh
./build_all_lambdas.sh
```

### 3. Configure Your Deployment

Create your Terraform configuration:

```hcl
module "scopedown" {
  source  = "./infra/terraform/modules/iam-parser"
  tf_path = "."

  # Environment Configuration
  environment = "production"
  github_repo = "your-org/your-infrastructure-repo"

  # Workflow Configuration
  create_step_function = true
  enable_daily_schedule = true
  schedule_expression = "cron(0 6 ? * SUN *)"  # Weekly analysis

  # CloudTrail Configuration
  enable_cloudtrail_data_lake = true
  cloudtrail_retention_days = 90

  # Security Configuration
  github_token_ssm_path = "/scopedown/github-token"
  
  # Monitoring Configuration
  enable_monitoring = true
  log_retention_days = 30

  # Resource Tagging
  tags = {
    Project     = "ScopeDown"
    Environment = "production"
    Owner       = "security-team"
    Purpose     = "Automated IAM least privilege enforcement"
    Compliance  = "SOC2-Type2"
  }
}
```

### 4. Deploy Infrastructure

```bash
terraform init
terraform plan
terraform apply
```

### 5. Configure GitHub Access

```bash
aws ssm put-parameter \
  --name '/scopedown/github-token' \
  --value 'ghp_your_token_here' \
  --type SecureString \
  --description 'GitHub token for ScopeDown PR automation'
```

### 6. Test the System

```bash
# Test the full workflow
aws stepfunctions start-execution \
  --state-machine-arn "arn:aws:states:region:account:stateMachine:scopedown-analyzer" \
  --input '{}'

# Monitor execution
aws stepfunctions describe-execution \
  --execution-arn "execution-arn-from-above"
```

---

##  Configuration Reference

### **Core Variables**

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `environment` | string | "dev" | Deployment environment |
| `github_repo` | string | required | Target repository for PRs |
| `create_step_function` | bool | true | Enable workflow automation |
| `enable_daily_schedule` | bool | false | Enable scheduled execution |
| `cloudtrail_retention_days` | number | 90 | Analysis time window |
| `enable_monitoring` | bool | true | CloudWatch monitoring |

### **Advanced Configuration**

```hcl
# Fine-tune Lambda performance
lambda_timeout = 300
lambda_memory_size = 1024

# Customize storage
s3_prefix = "iam-analysis"
force_destroy_bucket = false  # Set to true for testing

# Security settings
enable_test_mode = false
analyzer_arn = "arn:aws:access-analyzer:us-east-1:account:analyzer/name"

# Scheduling
schedule_expression = "cron(0 6 ? * SUN *)"  # Weekly on Sundays
```

---

## 📁 Project Structure

```
least-privilege-optimizer/
├── README.md                           # This documentation
├── infra/                             # Infrastructure components
│   ├── terraform/                     # Main Terraform root
│   │   └── modules/
│   │       └── iam-parser/           # Core ScopeDown module
│   │           ├── main.tf           # Module entry point
│   │           ├── variables.tf      # Configuration variables
│   │           ├── outputs.tf        # Module outputs
│   │           ├── lambda.tf         # Lambda function definitions
│   │           ├── step_function.tf  # Workflow orchestration
│   │           ├── cloudtrail-lake.tf # Usage analytics
│   │           ├── s3.tf            # Storage configuration
│   │           ├── iam_roles.tf     # IAM permissions
│   │           ├── kms.tf           # Encryption keys
│   │           └── lambda/          # Function source code
│   │               ├── build_all_lambdas.sh
│   │               ├── shared/      # Common utilities
│   │               ├── step1_read_s3/
│   │               ├── step2_cloudtrail/
│   │               ├── step3_query_status/
│   │               ├── step4_github_fetch/
│   │               ├── step5_parse_policies/
│   │               ├── step6_apply_modifications/
│   │               └── step7_github_pr/
│   └── sample-iac-app/               # Example application
│       ├── terraform/                # Sample Terraform configuration
│       └── sample-frontend/          # React TypeScript demo app
└── docs/                             # Additional documentation
```

---

## 🔍 How It Works: Detailed Workflow

### **Phase 1: Discovery & Analysis**
1. **IAM Inventory**: Scan Terraform files to build comprehensive IAM resource map
2. **Usage Tracking**: Query CloudTrail Lake for actual API usage patterns over configurable time periods
3. **Gap Analysis**: Compare granted permissions against observed usage using statistical analysis

### **Phase 2: Intelligent Optimization**
1. **Risk Assessment**: Identify high-impact, low-risk optimization opportunities
2. **Policy Generation**: Create least-privilege policies using AWS Access Analyzer validation
3. **Change Planning**: Generate detailed modification plans with security impact analysis

### **Phase 3: Automated Application**
1. **Safe Modifications**: Apply changes with built-in safeguards and rollback capabilities
2. **PR Generation**: Create comprehensive pull requests with detailed explanations
3. **Review Process**: Enable team review and approval before changes are merged

### **Phase 4: Continuous Monitoring**
1. **Scheduled Execution**: Automatic analysis runs on configurable schedules
2. **Drift Detection**: Identify new permission creep as it occurs
3. **Compliance Reporting**: Generate audit-ready reports for security reviews

---

## 🛡️ Security & Compliance Features

### **Built-in Security Controls**

- **Least Privilege by Design**: ScopeDown itself follows least privilege principles ensuring the deployed infrastructure is accessing only necessary resources.
- **Encryption at Rest**: All data encrypted using AWS managed encryption
- **Audit Logging**: Comprehensive CloudTrail integration for all API calls
- **Network Security**: VPC-compatible deployment with private subnet support

### **Risk Management**

- **Conservative Approach**: When in doubt, preserve existing access
- **Rollback Capabilities**: Quick reversal of changes if issues arise
- **Impact Analysis**: Clear documentation of security improvements
- **Change Control**: Integration with existing change management processes

---

## 📈 Monitoring & Observability

### **CloudWatch Integration**

- **Function Metrics**: Performance monitoring for all Lambda functions
- **Error Alerting**: Automatic notifications for workflow failures
- **Cost Tracking**: Monitor operational costs and optimization opportunities
- **Security Events**: Track security-relevant activities and changes

---

## 🧪 Testing & Development

### **Built-in Testing Framework**

```bash
# Run integration tests
cd infra/terraform/modules/iam-parser/lambda
python -m pytest test/ -v

# Test individual functions
aws lambda invoke --function-name scopedown-read-s3 response.json

# Test full workflow
aws stepfunctions start-execution \
  --state-machine-arn "arn:aws:states:region:account:stateMachine:scopedown" \
  --input '{"test_mode": true}'
```

### **Development Environment**

```bash
# Local development setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure test environment
cp .env.example .env
# Edit .env with your test configuration
```

---

## 🤝 Contributing & Support

### **Contributing to ScopeDown**

We welcome contributions from the community! This project represents the culmination of research and development in cloud security automation.

1. **Fork the Repository**: Create your own copy for development
2. **Create Feature Branch**: `git checkout -b feature/amazing-feature`
3. **Make Changes**: Follow our coding standards and documentation requirements
4. **Test Thoroughly**: Ensure all tests pass and add new tests for new features
5. **Submit Pull Request**: Provide detailed description of changes and impact

### **Academic Context**

This project was developed as part of the UC Berkeley Master of Information and Cybersecurity (MICS) program capstone requirement. It represents applied research in:

- **Cloud Security Automation**
- **Infrastructure as Code Security**
- **Behavioral Analytics for Access Control**
- **DevSecOps Integration Patterns**

### **Team**

- **Aish Joshi**
- **Bill Froemming**
- **David Kocen**
- **Matt Neith**

---

##  License

MIT License - see [LICENSE](./LICENSE) file for details.

---

## 🎓 Academic Recognition

**University of California, Berkeley**  
**Master of Information and Cybersecurity (MICS)**  
**Capstone Project 2025**

*"ScopeDown: Intelligent AWS IAM Least Privilege Automation"*

This project demonstrates the practical application of cybersecurity principles, cloud computing technologies, and automation frameworks to solve real-world security challenges in enterprise environments.

Code and documentation generated with the help of GitHub Copilot AI

---

*ScopeDown isn't just a tool—it's a paradigm shift toward continuous, automated security that scales with your organization's growth while maintaining the highest standards of least privilege access control.*
