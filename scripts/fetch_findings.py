import json
import boto3

# Load latest.json
with open('../lambdas/analyzer/modules/latest.json', 'r') as f:
    latest = json.load(f)

# Initialize Access Analyzer client
client = boto3.client('accessanalyzer', region_name='us-east-2')

# Set the analyzer name
ANALYZER_ARN = 'arn:aws:access-analyzer:us-east-2:904610147891:analyzer/scopedown-analyzer'

def get_findings_for_arn(analyzer_name, resource_arn):
    paginator = client.get_paginator('list_findings_v2')
    findings = []
    for page in paginator.paginate(analyzerArn=ANALYZER_ARN, filter={'resource': {'eq': [resource_arn]}}):
        findings.extend(page['findings'])
    return findings

# Collect findings for each IAM resource
all_findings = {}

for resource_type in ['aws_iam_user', 'aws_iam_role']:
    for resource in latest.get(resource_type, []):
        arn = resource['arn']
        tf_resource_name = resource['tf_resource_name']
        print(f"Fetching findings for {tf_resource_name} ({arn})...")
        findings = get_findings_for_arn(ANALYZER_ARN, arn)
        all_findings[tf_resource_name] = findings

# Save findings to a file for later use
with open('access_analyzer_findings.json', 'w') as f:
    json.dump(all_findings, f, indent=2)

print("Done! Findings written to access_analyzer_findings.json")
