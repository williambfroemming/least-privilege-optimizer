#!/bin/bash

# Build IAM Analyzer Lambda functions for Terraform deployment
# Usage: ./build_all_lambdas.sh

set -e

# Configuration - these should match your Terraform variables
RUNTIME="python3.9"

# Function directories (these should match your local.lambda_functions in lambda.tf)
DIRS=(
    "step1_read_s3"
    "step2_cloudtrail"
    "step3_query_status"
    "step4_github_fetch"
    "step5_parse_policies"
    "step6_apply_modifications"
    "step7_github_pr"
)

# Function names that map to Terraform locals
FUNCTION_KEYS=(
    "read-s3"
    "start-cloudtrail"
    "check-cloudtrail"
    "fetch-terraform"
    "parse-policies"
    "apply-modifications"
    "github-pr"
)

create_deployment_package() {
    local dir=$1
    local function_key=$2
    
    echo "Building function package for $function_key from $dir..."
    
    # Create function directory if it doesn't exist
    mkdir -p "$dir"
    
    # Check if index.py exists
    if [ ! -f "$dir/index.py" ]; then
        echo "Error: $dir/index.py not found!"
        echo "Please ensure all Lambda function files are in place."
        return 1
    fi
    
    # Create deployment package in the same directory
    cd "$dir"
    
    # Remove existing zip if present
    rm -f function.zip
    
    # Create zip package
    zip -r function.zip index.py
    
    # Go back to parent directory
    cd ..
    
    echo "Created $dir/function.zip"
}

validate_structure() {
    echo "Validating directory structure..."
    
    for i in "${!DIRS[@]}"; do
        dir="${DIRS[$i]}"
        if [ ! -d "$dir" ]; then
            echo "Error: Directory $dir not found!"
            echo "Expected structure:"
            echo "lambda/"
            for d in "${DIRS[@]}"; do
                echo "  $d/"
                echo "    index.py"
            done
            return 1
        fi
        
        if [ ! -f "$dir/index.py" ]; then
            echo "Error: $dir/index.py not found!"
            return 1
        fi
    done
    
    echo "Directory structure validation passed."
}

# Main execution
echo "IAM Analyzer Lambda Build Script"
echo "================================"

# Validate directory structure first
validate_structure

# Build all functions
echo ""
echo "Building all Lambda function packages..."

for i in "${!DIRS[@]}"; do
    create_deployment_package "${DIRS[$i]}" "${FUNCTION_KEYS[$i]}"
done

echo ""
echo "Build completed successfully!"
echo ""
echo "Created packages:"
for dir in "${DIRS[@]}"; do
    if [ -f "$dir/function.zip" ]; then
        size=$(ls -lh "$dir/function.zip" | awk '{print $5}')
        echo "  $dir/function.zip ($size)"
    fi
done

echo ""
echo "Next steps:"
echo "1. Run 'terraform plan' to see what will be created"
echo "2. Run 'terraform apply' to deploy the infrastructure"
echo "3. Set your GitHub token in SSM: aws ssm put-parameter --name '/github-tokens/iam-analyzer' --value 'your_token' --type SecureString"