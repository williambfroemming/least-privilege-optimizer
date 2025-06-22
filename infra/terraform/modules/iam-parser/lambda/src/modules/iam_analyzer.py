"""
AWS IAM Access Analyzer Wrapper Module

This module provides a clean, type-safe interface for AWS IAM Access Analyzer operations
including resource analysis, finding management, and policy operations.
"""

from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from aws_lambda_powertools import Logger

logger = Logger(service="IAMAnalyzer")


class ResourceType(Enum):
    """Supported IAM resource types for analysis"""
    USER = "AWS::IAM::User"
    ROLE = "AWS::IAM::Role"
    GROUP = "AWS::IAM::Group"
    POLICY = "AWS::IAM::Policy"


class FindingStatus(Enum):
    """Access Analyzer finding statuses"""
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    RESOLVED = "RESOLVED"


@dataclass
class IAMResource:
    """Represents an IAM resource to be analyzed"""
    arn: str
    resource_type: ResourceType
    name: str
    
    def __post_init__(self):
        """Validate resource data after initialization"""
        if not self.arn or not self.name:
            raise ValueError("Resource ARN and name are required")


@dataclass  
class FindingSummary:
    """Summary statistics for findings analysis"""
    total_findings: int
    findings_by_type: Dict[str, int]
    findings_by_status: Dict[str, int]
    findings_by_resource: Dict[str, int]


class AnalyzerError(Exception):
    """Custom exception for Analyzer operations"""
    pass


class IAMAnalyzer:
    """
    AWS IAM Access Analyzer client wrapper providing type-safe operations
    for IAM resource analysis, finding management, and policy operations.
    """
    
    def __init__(self, region: str = 'us-east-1') -> None:
        """
        Initialize the IAM Analyzer with AWS clients
        
        Args:
            region: AWS region for client initialization
            
        Raises:
            AnalyzerError: If client initialization fails
        """
        self.region = region
        self._initialize_clients()
        
    def _initialize_clients(self) -> None:
        """Initialize AWS service clients with error handling"""
        try:
            logger.info(f"Initializing AWS clients for region: {self.region}")
            self.access_analyzer = boto3.client('accessanalyzer', region_name=self.region)
            self.s3_client = boto3.client('s3', region_name=self.region)
            logger.info("Successfully initialized AWS clients")
        except Exception as e:
            error_msg = f"Failed to initialize AWS clients: {str(e)}"
            logger.error(error_msg)
            raise AnalyzerError(error_msg) from e

    # =============================================================================
    # Resource Management Operations
    # =============================================================================
    
    def fetch_resources_from_s3(self, bucket_name: str, prefix: str) -> List[IAMResource]:
        """
        Fetch IAM resources from S3 and convert to typed objects
        
        Args:
            bucket_name: S3 bucket containing resource data
            prefix: S3 key prefix for the resource file
            
        Returns:
            List of typed IAM resources ready for analysis
            
        Raises:
            AnalyzerError: If S3 fetch or parsing fails
        """
        self._validate_s3_params(bucket_name, prefix)
        
        try:
            logger.info(f"Fetching resources from s3://{bucket_name}/{prefix}")
            raw_data = self._fetch_s3_object(bucket_name, prefix)
            resources = self._parse_resource_data(raw_data)
            
            logger.info(f"Successfully parsed {len(resources)} IAM resources")
            self._log_resource_summary(resources)
            
            return resources
            
        except Exception as e:
            error_msg = f"Failed to fetch resources from S3: {str(e)}"
            logger.error(error_msg)
            raise AnalyzerError(error_msg) from e
    
    def _validate_s3_params(self, bucket_name: str, prefix: str) -> None:
        """Validate S3 parameters"""
        if not bucket_name or not prefix:
            raise ValueError("Both bucket_name and prefix are required")
    
    def _fetch_s3_object(self, bucket_name: str, prefix: str) -> Dict[str, Any]:
        """Fetch and parse JSON from S3"""
        s3_key = f"{prefix.rstrip('/')}/latest.json"
        logger.info(f"Fetching S3 object: {s3_key}")
        
        try:
            response = self.s3_client.get_object(Bucket=bucket_name, Key=s3_key)
            content_size = response.get('ContentLength', 0)
            logger.info(f"Retrieved S3 object ({content_size} bytes)")
            
            raw_data = json.loads(response['Body'].read().decode('utf-8'))
            return raw_data.get("resources", {})
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            logger.error(f"S3 ClientError [{error_code}]: {str(e)}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in S3 object: {str(e)}")
            raise
    
    def _parse_resource_data(self, raw_data: Dict[str, Any]) -> List[IAMResource]:
        """Parse raw S3 data into typed IAM resources"""
        resources: List[IAMResource] = []
        
        # Resource type mapping for cleaner processing
        resource_mappings = {
            'aws_iam_user': ResourceType.USER,
            'aws_iam_role': ResourceType.ROLE,
            'aws_iam_group': ResourceType.GROUP,
            'aws_iam_policy': ResourceType.POLICY
        }
        
        logger.info(f"Processing resource categories: {list(raw_data.keys())}")
        
        for category, resource_type in resource_mappings.items():
            raw_resources = raw_data.get(category, [])
            parsed_count = self._process_resource_category(
                raw_resources, resource_type, resources
            )
            logger.info(f"Processed {parsed_count}/{len(raw_resources)} {category} resources")
        
        return resources
    
    def _process_resource_category(
        self, 
        raw_resources: List[Dict[str, Any]], 
        resource_type: ResourceType,
        resources: List[IAMResource]
    ) -> int:
        """Process a single category of resources"""
        processed_count = 0
        
        for raw_resource in raw_resources:
            try:
                if self._is_valid_resource(raw_resource):
                    resource = IAMResource(
                        arn=raw_resource['arn'],
                        resource_type=resource_type,
                        name=raw_resource['name']
                    )
                    resources.append(resource)
                    processed_count += 1
                    logger.debug(f"Added {resource_type.value}: {resource.name}")
                else:
                    logger.warning(f"Skipping invalid {resource_type.value}: {raw_resource}")
                    
            except (KeyError, ValueError) as e:
                logger.warning(f"Failed to process {resource_type.value}: {str(e)}")
                continue
        
        return processed_count
    
    def _is_valid_resource(self, resource: Dict[str, Any]) -> bool:
        """Check if a resource has required fields"""
        return bool(resource.get('arn') and resource.get('name'))
    
    def _log_resource_summary(self, resources: List[IAMResource]) -> None:
        """Log summary of processed resources"""
        summary = {}
        for resource in resources:
            resource_type = resource.resource_type.value
            summary[resource_type] = summary.get(resource_type, 0) + 1
        
        logger.info(f"Resource summary: {summary}")
        
        if logger.level == "DEBUG":
            logger.debug("Complete resource listing:")
            for i, resource in enumerate(resources, 1):
                logger.debug(f"  {i}. {resource.resource_type.value}: {resource.name} ({resource.arn})")

    # =============================================================================
    # Findings Operations
    # =============================================================================
    
    def list_findings_for_resources(
        self, 
        analyzer_arn: str, 
        resources: List[IAMResource]
    ) -> Tuple[List[Dict[str, Any]], FindingSummary]:
        """
        Get all findings for specific IAM resources
        
        Args:
            analyzer_arn: ARN of the Access Analyzer
            resources: List of IAM resources to analyze
            
        Returns:
            Tuple of (findings list, summary statistics)
            
        Raises:
            AnalyzerError: If findings retrieval fails
        """
        if not analyzer_arn or not resources:
            raise ValueError("analyzer_arn and resources are required")
        
        try:
            logger.info(f"Fetching findings for {len(resources)} resources")
            resource_arns = [resource.arn for resource in resources]
            
            findings = self._fetch_findings_by_resources(analyzer_arn, resource_arns)
            summary = self._create_finding_summary(findings)
            
            logger.info(f"Retrieved {len(findings)} findings")
            self._log_finding_details(findings, summary)
            
            return findings, summary
            
        except Exception as e:
            error_msg = f"Failed to list findings: {str(e)}"
            logger.error(error_msg)
            raise AnalyzerError(error_msg) from e
    
    def _fetch_findings_by_resources(
        self, 
        analyzer_arn: str, 
        resource_arns: List[str]
    ) -> List[Dict[str, Any]]:
        """Fetch findings filtered by specific resource ARNs"""
        resource_filter = {
            'resource': {
                'contains': resource_arns
            }
        }
        
        logger.debug(f"Using resource filter: {json.dumps(resource_filter, indent=2)}")
        
        try:
            response = self.access_analyzer.list_findings_v2(
                analyzerArn=analyzer_arn,
                filter=resource_filter
            )
            return response.get('findings', [])
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            logger.error(f"AccessAnalyzer ClientError [{error_code}]: {str(e)}")
            raise
    
    def _create_finding_summary(self, findings: List[Dict[str, Any]]) -> FindingSummary:
        """Create statistical summary of findings"""
        findings_by_type: Dict[str, int] = {}
        findings_by_status: Dict[str, int] = {}
        findings_by_resource: Dict[str, int] = {}
        
        for finding in findings:
            # Count by type
            finding_type = finding.get('findingType', 'unknown')
            findings_by_type[finding_type] = findings_by_type.get(finding_type, 0) + 1
            
            # Count by status
            status = finding.get('status', 'unknown')
            findings_by_status[status] = findings_by_status.get(status, 0) + 1
            
            # Count by resource - handle different resource field types
            resource_arn = self._extract_resource_arn(finding)
            findings_by_resource[resource_arn] = findings_by_resource.get(resource_arn, 0) + 1
        
        return FindingSummary(
            total_findings=len(findings),
            findings_by_type=findings_by_type,
            findings_by_status=findings_by_status,
            findings_by_resource=findings_by_resource
        )
    
    def _extract_resource_arn(self, finding: Dict[str, Any]) -> str:
        """
        Safely extract resource ARN from finding, handling different data structures
        
        Args:
            finding: Access Analyzer finding
            
        Returns:
            Resource ARN or 'unknown' if not found
        """
        try:
            resource = finding.get('resource')
            
            if resource is None:
                logger.debug(f"Finding {finding.get('id', 'unknown')} has no resource field")
                return 'unknown'
            
            # Handle case where resource is a dictionary (expected)
            if isinstance(resource, dict):
                return resource.get('arn', 'unknown')
            
            # Handle case where resource is a string (the ARN itself)
            elif isinstance(resource, str):
                logger.debug(f"Finding {finding.get('id', 'unknown')} has resource as string: {resource}")
                return resource
            
            # Handle unexpected resource type
            else:
                logger.warning(f"Finding {finding.get('id', 'unknown')} has unexpected resource type: {type(resource)}")
                return 'unknown'
                
        except Exception as e:
            logger.warning(f"Error extracting resource ARN from finding {finding.get('id', 'unknown')}: {str(e)}")
            return 'unknown'
    
    def _log_finding_details(self, findings: List[Dict[str, Any]], summary: FindingSummary) -> None:
        """Log detailed information about findings"""
        logger.info(f"Finding types: {summary.findings_by_type}")
        logger.info(f"Finding statuses: {summary.findings_by_status}")
        logger.info(f"Findings per resource: {summary.findings_by_resource}")
        
        if findings and logger.level == "INFO":
            logger.info("Finding details:")
            for i, finding in enumerate(findings, 1):
                resource_arn = self._extract_resource_arn(finding)
                finding_id = finding.get('id', 'unknown')
                finding_type = finding.get('findingType', 'unknown')
                status = finding.get('status', 'unknown')
                logger.info(f"  {i}. {finding_id} | {finding_type} | {status} | {resource_arn}")
    
    def get_finding_details(self, analyzer_arn: str, finding_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific finding
        
        Args:
            analyzer_arn: ARN of the Access Analyzer
            finding_id: ID of the finding to retrieve
            
        Returns:
            Complete finding details
            
        Raises:
            AnalyzerError: If finding retrieval fails
        """
        if not analyzer_arn or not finding_id:
            raise ValueError("analyzer_arn and finding_id are required")
        
        try:
            logger.info(f"Retrieving finding details: {finding_id}")
            
            response = self.access_analyzer.get_finding(
                analyzerArn=analyzer_arn,
                id=finding_id
            )
            
            finding = response['finding']
            self._log_finding_summary(finding)
            
            return finding
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = f"Failed to get finding [{error_code}]: {str(e)}"
            logger.error(error_msg)
            raise AnalyzerError(error_msg) from e
    
    def _log_finding_summary(self, finding: Dict[str, Any]) -> None:
        """Log key information about a finding"""
        resource_arn = self._extract_resource_arn(finding)
        finding_type = finding.get('findingType', 'unknown')
        status = finding.get('status', 'unknown')
        created_at = finding.get('createdAt', 'unknown')
        
        logger.info(f"Finding summary: {finding_type} | {status} | {resource_arn} | {created_at}")
    
    def update_finding_status(
        self, 
        analyzer_arn: str, 
        finding_ids: List[str], 
        status: Union[FindingStatus, str]
    ) -> None:
        """
        Update the status of multiple findings
        
        Args:
            analyzer_arn: ARN of the Access Analyzer
            finding_ids: List of finding IDs to update
            status: New status to set (enum or string)
            
        Raises:
            AnalyzerError: If status update fails
        """
        if not analyzer_arn or not finding_ids:
            raise ValueError("analyzer_arn and finding_ids are required")
        
        # Handle both enum and string status
        status_str = status.value if isinstance(status, FindingStatus) else str(status)
        
        try:
            logger.info(f"Updating {len(finding_ids)} findings to status: {status_str}")
            
            self.access_analyzer.update_findings(
                analyzerArn=analyzer_arn,
                ids=finding_ids,
                status=status_str
            )
            
            logger.info(f"Successfully updated findings to {status_str}")
            for finding_id in finding_ids:
                logger.debug(f"Updated finding {finding_id} to {status_str}")
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = f"Failed to update findings [{error_code}]: {str(e)}"
            logger.error(error_msg)
            raise AnalyzerError(error_msg) from e

    # =============================================================================
    # Policy Operations
    # =============================================================================
    
    def generate_policy(self, policy_type: str, configuration: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate IAM policy using Access Analyzer
        
        Args:
            policy_type: Type of policy to generate
            configuration: Policy generation configuration
            
        Returns:
            Generated policy document
            
        Raises:
            AnalyzerError: If policy generation fails
        """
        if not policy_type or not configuration:
            raise ValueError("policy_type and configuration are required")
        
        try:
            logger.info(f"Starting policy generation: {policy_type}")
            logger.debug(f"Configuration: {json.dumps(configuration, indent=2)}")
            
            # Start policy generation job
            response = self.access_analyzer.start_policy_generation(
                policyType=policy_type,
                policyGenerationDetails=configuration
            )
            
            job_id = response['jobId']
            logger.info(f"Policy generation job started: {job_id}")
            
            # Wait for completion
            self._wait_for_policy_generation(job_id)
            
            # Retrieve generated policy
            policy = self._get_generated_policy(job_id)
            
            logger.info(f"Policy generation completed for job: {job_id}")
            return policy
            
        except Exception as e:
            error_msg = f"Policy generation failed: {str(e)}"
            logger.error(error_msg)
            raise AnalyzerError(error_msg) from e
    
    def _wait_for_policy_generation(self, job_id: str) -> None:
        """Wait for policy generation to complete"""
        logger.info(f"Waiting for policy generation completion: {job_id}")
        waiter = self.access_analyzer.get_waiter('policy_generation_complete')
        waiter.wait(jobId=job_id)
        logger.info(f"Policy generation completed: {job_id}")
    
    def _get_generated_policy(self, job_id: str) -> Dict[str, Any]:
        """Retrieve generated policy from completed job"""
        response = self.access_analyzer.get_generated_policy(jobId=job_id)
        policy = response['generatedPolicy']
        logger.debug(f"Generated policy: {json.dumps(policy, indent=2)}")
        return policy
    
    def validate_policy(self, policy_document: str, policy_type: str = 'IAM') -> List[Dict[str, Any]]:
        """
        Validate IAM policy document
        
        Args:
            policy_document: Policy document JSON string
            policy_type: Type of policy to validate
            
        Returns:
            List of validation findings
            
        Raises:
            AnalyzerError: If policy validation fails
        """
        if not policy_document:
            raise ValueError("policy_document is required")
        
        try:
            logger.info(f"Validating {policy_type} policy")
            logger.debug(f"Policy preview: {policy_document[:200]}...")
            
            response = self.access_analyzer.validate_policy(
                policyDocument=policy_document,
                policyType=policy_type
            )
            
            findings = response.get('findings', [])
            self._log_validation_results(findings)
            
            return findings
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = f"Policy validation failed [{error_code}]: {str(e)}"
            logger.error(error_msg)
            raise AnalyzerError(error_msg) from e
    
    def _log_validation_results(self, findings: List[Dict[str, Any]]) -> None:
        """Log policy validation results"""
        if not findings:
            logger.info("Policy validation passed - no issues found")
            return
        
        logger.warning(f"Policy validation found {len(findings)} issues")
        finding_types = {}
        
        for finding in findings:
            finding_type = finding.get('findingType', 'unknown')
            finding_types[finding_type] = finding_types.get(finding_type, 0) + 1
            logger.warning(f"Validation issue: {finding_type} - {finding.get('findingDetails', 'No details')}")
        
        logger.info(f"Validation findings breakdown: {finding_types}")

    # =============================================================================
    # Analyzer Management Operations  
    # =============================================================================
    
    def list_analyzers(self) -> List[Dict[str, Any]]:
        """
        List all Access Analyzers in the account
        
        Returns:
            List of analyzer configurations
            
        Raises:
            AnalyzerError: If analyzer listing fails
        """
        try:
            logger.info("Listing Access Analyzers")
            
            response = self.access_analyzer.list_analyzers()
            analyzers = response.get('analyzers', [])
            
            logger.info(f"Found {len(analyzers)} Access Analyzers")
            self._log_analyzer_details(analyzers)
            
            return analyzers
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = f"Failed to list analyzers [{error_code}]: {str(e)}"
            logger.error(error_msg)
            raise AnalyzerError(error_msg) from e
    
    def _log_analyzer_details(self, analyzers: List[Dict[str, Any]]) -> None:
        """Log details of available analyzers"""
        if not analyzers:
            logger.warning("No Access Analyzers found")
            return
        
        logger.info("Available analyzers:")
        for i, analyzer in enumerate(analyzers, 1):
            name = analyzer.get('name', 'unknown')
            arn = analyzer.get('arn', 'unknown')
            status = analyzer.get('status', 'unknown')
            analyzer_type = analyzer.get('type', 'unknown')
            created_at = analyzer.get('createdAt', 'unknown')
            
            logger.info(f"  {i}. {name} | {status} | {analyzer_type} | {created_at}")
            logger.debug(f"     ARN: {arn}")

    # =============================================================================
    # Convenience Methods
    # =============================================================================
    
    def analyze_resources_from_s3(
        self, 
        analyzer_arn: str, 
        bucket_name: str, 
        prefix: str
    ) -> Tuple[List[IAMResource], List[Dict[str, Any]], FindingSummary]:
        """
        Complete workflow: fetch resources from S3 and analyze findings
        
        Args:
            analyzer_arn: ARN of the Access Analyzer
            bucket_name: S3 bucket containing resource data
            prefix: S3 key prefix for the resource file
            
        Returns:
            Tuple of (resources, findings, summary)
            
        Raises:
            AnalyzerError: If any step of the analysis fails
        """
        logger.info("Starting complete resource analysis workflow")
        
        # Fetch resources from S3
        resources = self.fetch_resources_from_s3(bucket_name, prefix)
        
        # Get findings for those resources
        findings, summary = self.list_findings_for_resources(analyzer_arn, resources)
        
        logger.info("Analysis workflow completed successfully")
        return resources, findings, summary


# Maintain backwards compatibility with original class name
Analyzer = IAMAnalyzer

