from typing import Dict, List, Optional
import json
import os
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
import boto3
from botocore.exceptions import ClientError

logger = Logger(service="Analyzer")

class Analyzer:
    """Wrapper class for AWS IAM Access Analyzer operations"""
    
    def __init__(self, region: str = 'us-east-1'):
        """Initialize Access Analyzer client
        
        Args:
            region: AWS region name (defaults to us-east-1)
        """
        self.client = boto3.client('accessanalyzer', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)
    
    def fetch_resources_to_analyze(self, bucket_name: str, prefix: str) -> List[Dict]:
        """Fetch IAM resources to analyze from S3
        
        Args:
            bucket_name: Name of the S3 bucket containing IAM resources
            prefix: S3 prefix where the resources are stored
            
        Returns:
            List of IAM resources to analyze with their ARNs
        """
        if not bucket_name or not prefix:
            raise ValueError("bucket_name and prefix are required")
            
        try:
            s3_key = f"{prefix.rstrip('/')}/latest.json"
            response = self.s3.get_object(
                Bucket=bucket_name,
                Key=s3_key
            )
            raw_resources = json.loads(response['Body'].read().decode('utf-8'))["resources"]
            
            # Extract resources and their ARNs from the format
            resources = []
            
            # Process users
            for user in raw_resources.get('aws_iam_user', []):
                resources.append({
                    'ResourceARN': user['arn'],
                    'ResourceType': 'AWS::IAM::User',
                    'ResourceName': user['name']
                })
                
            # Process roles
            for role in raw_resources.get('aws_iam_role', []):
                resources.append({
                    'ResourceARN': role['arn'],
                    'ResourceType': 'AWS::IAM::Role',
                    'ResourceName': role['name']
                })
                
            # Process groups if they exist
            for group in raw_resources.get('aws_iam_group', []):
                if 'arn' in group:
                    resources.append({
                        'ResourceARN': group['arn'],
                        'ResourceType': 'AWS::IAM::Group',
                        'ResourceName': group['name']
                    })
                    
            # Process standalone policies if they exist
            for policy in raw_resources.get('aws_iam_policy', []):
                if 'arn' in policy:
                    resources.append({
                        'ResourceARN': policy['arn'],
                        'ResourceType': 'AWS::IAM::Policy',
                        'ResourceName': policy['name']
                    })
            
            logger.info(f"Successfully fetched {len(resources)} resources to analyze")
            return resources
            
        except ClientError as e:
            logger.error(f"Error fetching resources from S3: {str(e)}")
            raise

    def list_findings(self, analyzer_arn: str, bucket_name: str, prefix: str) -> List[Dict]:
        """List findings from IAM Access Analyzer
        
        Args:
            analyzer_arn: ARN of the IAM Access Analyzer
            bucket_name: Name of the S3 bucket for storing findings
            prefix: S3 prefix where the findings should be stored
            
        Returns:
            List of findings from the analyzer
        """
        if not analyzer_arn or not bucket_name or not prefix:
            raise ValueError("analyzer_arn, bucket_name, and prefix are required")
            
        try:
            # Fetch resources to analyze with updated parameters
            resources = self.fetch_resources_to_analyze(bucket_name, prefix)
            resource_arns = [resource['ResourceARN'] for resource in resources]
            logger.info(f"Analyzing {len(resource_arns)} resources from S3")
            
            # Get all findings
            response = self.client.list_findings_v2(
                analyzerArn=analyzer_arn,
                filter={
                    'findingType': {
                        'contains': ['UNUSED_ACCESS']
                    }
                }
            )
            findings = response.get('findings', [])
            
            # Filter findings by the resources we are analyzing
            findings = [
                finding for finding in findings 
                if finding.get('resource', {}).get('arn') in resource_arns
            ]
            logger.info(f"Found {len(findings)} findings for specified resources")
                
            return findings
            
        except Exception as e:
            logger.error(f"Error listing findings: {str(e)}")
            raise
    
    def generate_policy(self, policy_type: str, configuration: Dict) -> Dict:
        """Generate IAM policy using Access Analyzer
        
        Args:
            policy_type: Type of policy to generate
            configuration: Policy generation configuration
            
        Returns:
            Generated policy document
        """
        try:
            response = self.client.start_policy_generation(
                policyType=policy_type,
                policyGenerationDetails=configuration
            )
            
            job_id = response['jobId']
            logger.info(f"Started policy generation job {job_id}")
            
            waiter = self.client.get_waiter('policy_generation_complete')
            waiter.wait(jobId=job_id)
            
            policy = self.client.get_generated_policy(jobId=job_id)
            logger.info(f"Generated policy for job {job_id}")
            return policy['generatedPolicy']
            
        except ClientError as e:
            logger.error(f"Error generating policy: {str(e)}")
            raise
            
    def validate_policy(self, policy_document: str, policy_type: str = 'IAM') -> Dict:
        """Validate IAM policy using Access Analyzer
        
        Args:
            policy_document: Policy document to validate
            policy_type: Type of policy to validate
            
        Returns:
            Validation findings
        """
        try:
            response = self.client.validate_policy(
                policyDocument=policy_document,
                policyType=policy_type
            )
            
            findings = response.get('findings', [])
            logger.info(f"Found {len(findings)} validation findings")
            return findings
            
        except ClientError as e:
            logger.error(f"Error validating policy: {str(e)}")
            raise
            
    def get_finding(self, analyzer_arn: str, finding_id: str) -> Dict:
        """Get details of a specific finding
        
        Args:
            analyzer_arn: ARN of the analyzer
            finding_id: ID of the finding
            
        Returns:
            Finding details
        """
        try:
            response = self.client.get_finding(
                analyzerArn=analyzer_arn,
                id=finding_id
            )
            
            logger.info(f"Retrieved finding {finding_id}")
            return response['finding']
            
        except ClientError as e:
            logger.error(f"Error getting finding details: {str(e)}")
            raise
            
    def list_analyzers(self) -> List[Dict]:
        """List Access Analyzers in the account
        
        Returns:
            List of analyzers
        """
        try:
            response = self.client.list_analyzers()
            analyzers = response.get('analyzers', [])
            logger.info(f"Retrieved {len(analyzers)} analyzers")
            return analyzers
            
        except ClientError as e:
            logger.error(f"Error listing analyzers: {str(e)}")
            raise
            
    def update_findings(self, analyzer_arn: str, finding_ids: List[str], status: str) -> None:
        """Update status of findings
        
        Args:
            analyzer_arn: ARN of the analyzer
            finding_ids: List of finding IDs to update
            status: New status to set
        """
        try:
            self.client.update_findings(
                analyzerArn=analyzer_arn,
                ids=finding_ids,
                status=status
            )
            logger.info(f"Updated {len(finding_ids)} findings to status {status}")
            
        except ClientError as e:
            logger.error(f"Error updating findings: {str(e)}")
            raise

