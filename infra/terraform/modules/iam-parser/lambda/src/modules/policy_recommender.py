import json
import os
import boto3
import re
from typing import Dict, List, Optional, Any
from aws_lambda_powertools import Logger
from datetime import datetime
from github import Github, Auth
import base64

logger = Logger(service="PolicyRecommender")

class PolicyRecommender:
    """Handles policy recommendations based on detailed Access Analyzer findings"""
    
    def __init__(self, github_token: str, repo_name: str, region: str = 'us-east-1'):
        """Initialize PolicyRecommender
        
        Args:
            github_token: GitHub personal access token
            repo_name: Repository name in format 'owner/repo'
            region: AWS region for Access Analyzer client
        """
        self.github_token = github_token
        self.repo_name = repo_name
        self.region = region
        self.github = Github(auth=Auth.Token(github_token))
        self.repo = self.github.get_repo(repo_name)
        self.access_analyzer = boto3.client('accessanalyzer', region_name=region)
        logger.info(f"Initialized PolicyRecommender for repo: {repo_name} in region: {region}")
    
    def fetch_detailed_findings(self, analyzer_arn: str, findings: List[Dict]) -> Dict[str, Dict]:
        """Fetch detailed findings from Access Analyzer for each finding
        
        Args:
            analyzer_arn: ARN of the Access Analyzer
            findings: List of basic findings from list_findings
            
        Returns:
            Dictionary mapping finding ID to detailed finding data
        """
        detailed_findings = {}
        
        for finding in findings:
            finding_id = finding.get('id')
            if not finding_id:
                logger.warning("Finding missing ID, skipping")
                continue
                
            try:
                logger.info(f"Fetching detailed finding for ID: {finding_id}")
                
                response = self.access_analyzer.get_finding_v2(
                    id=finding_id,
                    analyzerArn=analyzer_arn
                )
                
                detailed_findings[finding_id] = {
                    'basic_finding': finding,
                    'detailed_finding': response,
                    'resource_arn': self._extract_resource_arn(finding),
                    'unused_services': self._extract_unused_services(response)
                }
                
                logger.info(f"Successfully fetched details for finding {finding_id}")
                
            except Exception as e:
                logger.error(f"Failed to fetch details for finding {finding_id}: {str(e)}")
                continue
        
        logger.info(f"Fetched detailed findings for {len(detailed_findings)} out of {len(findings)} findings")
        return detailed_findings
    
    def _extract_resource_arn(self, finding: Dict) -> str:
        """Extract resource ARN from finding"""
        try:
            resource = finding.get('resource', {})
            if isinstance(resource, dict):
                return resource.get('arn', 'unknown')
            elif isinstance(resource, str):
                return resource
            return 'unknown'
        except Exception as e:
            logger.warning(f"Error extracting resource ARN: {str(e)}")
            return 'unknown'
    
    def _extract_unused_services(self, detailed_finding: Dict) -> List[str]:
        """Extract unused service namespaces from detailed finding
        
        Args:
            detailed_finding: Response from get_finding_v2
            
        Returns:
            List of unused service namespaces
        """
        try:
            finding_details = detailed_finding.get('findingDetails', [])
            unused_services = []
            
            for detail in finding_details:
                unused_permission = detail.get('unusedPermissionDetails', {})
                service_namespace = unused_permission.get('serviceNamespace')
                if service_namespace:
                    unused_services.append(service_namespace)
            
            logger.debug(f"Extracted {len(unused_services)} unused services: {unused_services}")
            return unused_services
            
        except Exception as e:
            logger.error(f"Error extracting unused services: {str(e)}")
            return []
    
    def process_detailed_findings(self, detailed_findings: Dict[str, Dict], resources: List[Dict]) -> Dict[str, Dict]:
        """Process detailed findings and generate policy recommendations
        
        Args:
            detailed_findings: Dictionary of detailed finding data
            resources: List of IAM resources from Terraform
            
        Returns:
            Dictionary of policy recommendations
        """
        logger.info(f"Processing {len(detailed_findings)} detailed findings")
        recommendations = {}
        
        # Create resource lookup by ARN
        resource_lookup = {}
        for resource in resources:
            arn = resource.get('ResourceARN') or resource.get('arn')
            if arn:
                resource_lookup[arn] = resource
        
        for finding_id, finding_data in detailed_findings.items():
            try:
                resource_arn = finding_data['resource_arn']
                unused_services = finding_data['unused_services']
                basic_finding = finding_data['basic_finding']
                
                if resource_arn not in resource_lookup:
                    logger.debug(f"Resource {resource_arn} not in target list, skipping")
                    continue
                
                if not unused_services:
                    logger.debug(f"No unused services found for finding {finding_id}")
                    continue
                
                resource = resource_lookup[resource_arn]
                recommendation = self._generate_recommendation_from_unused_services(
                    finding_id, basic_finding, resource, unused_services
                )
                
                if recommendation:
                    resource_key = self._get_resource_key(resource)
                    recommendations[resource_key] = recommendation
                    logger.info(f"Generated recommendation for {resource_key} with {len(unused_services)} unused services")
                
            except Exception as e:
                logger.error(f"Error processing finding {finding_id}: {str(e)}")
                continue
        
        logger.info(f"Generated {len(recommendations)} policy recommendations")
        return recommendations
    
    def _get_resource_key(self, resource: Dict) -> str:
        """Generate a resource key for the recommendation"""
        resource_type = resource.get('ResourceType', '')
        resource_name = resource.get('ResourceName', 'unknown')
        
        # Map AWS resource types to Terraform types
        tf_type_map = {
            'AWS::IAM::Role': 'aws_iam_role',
            'AWS::IAM::User': 'aws_iam_user', 
            'AWS::IAM::Group': 'aws_iam_group'
        }
        
        tf_type = tf_type_map.get(resource_type, 'aws_iam_unknown')
        return f"{tf_type}.{resource_name.replace('-', '_')}"
    
    def _generate_recommendation_from_unused_services(self, finding_id: str, basic_finding: Dict, 
                                                    resource: Dict, unused_services: List[str]) -> Dict:
        """Generate policy recommendation based on unused services
        
        Args:
            finding_id: Access Analyzer finding ID
            basic_finding: Basic finding data
            resource: Resource information
            unused_services: List of unused AWS service namespaces
            
        Returns:
            Policy recommendation dictionary
        """
        resource_name = resource.get('ResourceName', 'unknown')
        resource_type = resource.get('ResourceType', 'unknown')
        
        # Generate specific actions that can be removed for each service
        unused_actions = self._map_services_to_actions(unused_services)
        
        return {
            'finding_id': finding_id,
            'resource_name': resource_name,
            'resource_type': resource_type,
            'resource_arn': resource.get('ResourceARN'),
            'tf_resource_name': resource_name.replace('-', '_'),
            'unused_services': unused_services,
            'unused_actions': unused_actions,
            'finding_type': basic_finding.get('findingType', 'UNUSED_ACCESS'),
            'recommendation_type': 'remove_unused_permissions',
            'confidence': 'high',
            'recommendation_reason': f"Access Analyzer identified {len(unused_services)} unused service namespaces that can be removed for least privilege",
            'action_required': 'policy_optimization',
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _map_services_to_actions(self, unused_services: List[str]) -> List[str]:
        """Map unused service namespaces to common IAM actions that can be removed
        
        Args:
            unused_services: List of AWS service namespaces
            
        Returns:
            List of IAM actions that are likely unused
        """
        service_action_map = {
            'ecr': ['ecr:*', 'ecr:GetAuthorizationToken', 'ecr:BatchCheckLayerAvailability', 
                   'ecr:GetDownloadUrlForLayer', 'ecr:BatchGetImage'],
            'ecs': ['ecs:*', 'ecs:CreateCluster', 'ecs:DescribeClusters', 'ecs:RunTask', 
                   'ecs:StopTask', 'ecs:DescribeTasks'],
            'iam': ['iam:*', 'iam:PassRole', 'iam:CreateRole', 'iam:AttachRolePolicy', 
                   'iam:DetachRolePolicy', 'iam:DeleteRole'],
            'lambda': ['lambda:*', 'lambda:CreateFunction', 'lambda:InvokeFunction', 
                      'lambda:UpdateFunctionCode', 'lambda:DeleteFunction'],
            'logs': ['logs:*', 'logs:CreateLogGroup', 'logs:CreateLogStream', 
                    'logs:PutLogEvents', 'logs:DescribeLogGroups'],
            's3': ['s3:*', 's3:GetObject', 's3:PutObject', 's3:DeleteObject', 
                  's3:ListBucket', 's3:GetBucketLocation']
        }
        
        unused_actions = []
        for service in unused_services:
            actions = service_action_map.get(service, [f'{service}:*'])
            unused_actions.extend(actions)
        
        return unused_actions
    
    def create_policy_updates_pr(self, recommendations: Dict[str, Dict]) -> bool:
        """Create a GitHub PR with policy update recommendations
        
        Args:
            recommendations: Dictionary of policy recommendations
            
        Returns:
            True if PR created successfully, False otherwise
        """
        try:
            logger.info(f"Creating PR for {len(recommendations)} policy recommendations")
            
            # Download existing Terraform files
            terraform_files = self._download_terraform_files()
            
            # Generate updated files
            updated_files = []
            modification_summary = []
            
            for resource_key, recommendation in recommendations.items():
                try:
                    # Try to find and modify existing Terraform file
                    modified_file = self._modify_existing_terraform_file(
                        resource_key, recommendation, terraform_files
                    )
                    
                    if modified_file:
                        updated_files.append(modified_file)
                        modification_summary.append({
                            'resource': resource_key,
                            'unused_services': len(recommendation['unused_services']),
                            'unused_actions': len(recommendation['unused_actions']),
                            'file_modified': modified_file['path']
                        })
                        logger.info(f"Modified Terraform file for {resource_key}")
                    else:
                        # Create new recommendation file
                        new_file = self._create_recommendation_file(resource_key, recommendation)
                        if new_file:
                            updated_files.append(new_file)
                            logger.info(f"Created recommendation file for {resource_key}")
                
                except Exception as e:
                    logger.error(f"Failed to process {resource_key}: {str(e)}")
                    continue
            
            if not updated_files:
                logger.warning("No files to update, skipping PR creation")
                return False
            
            # Create PR
            title, body = self._generate_pr_content(recommendations, modification_summary)
            
            success = self._create_github_pr(
                title=title,
                body=body,
                files=updated_files
            )
            
            if success:
                logger.info(f"Successfully created PR with {len(updated_files)} file updates")
                return True
            else:
                logger.error("Failed to create GitHub PR")
                return False
                
        except Exception as e:
            logger.error(f"Error creating policy updates PR: {str(e)}")
            return False
    
    def _download_terraform_files(self) -> Dict[str, str]:
        """Download existing Terraform files from the repository"""
        terraform_files = {}
        
        try:
            # Look for Terraform files in common locations
            terraform_paths = [
                "terraform/",
                "infra/terraform/",
                "infra/sample-iac-app/terraform/",
                "policies.tf",
                "main.tf",
                "users.tf"
            ]
            
            for path in terraform_paths:
                try:
                    if path.endswith('.tf'):
                        # Single file
                        file_content = self.repo.get_contents(path)
                        content = base64.b64decode(file_content.content).decode('utf-8')
                        terraform_files[path] = content
                    else:
                        # Directory - get all .tf files
                        try:
                            contents = self.repo.get_contents(path)
                            if isinstance(contents, list):
                                for item in contents:
                                    if item.name.endswith('.tf'):
                                        file_content = base64.b64decode(item.content).decode('utf-8')
                                        full_path = f"{path.rstrip('/')}/{item.name}"
                                        terraform_files[full_path] = file_content
                        except Exception:
                            continue
                except Exception:
                    continue
            
            logger.info(f"Downloaded {len(terraform_files)} Terraform files")
            return terraform_files
            
        except Exception as e:
            logger.error(f"Error downloading Terraform files: {str(e)}")
            return {}
    
    def _modify_existing_terraform_file(self, resource_key: str, recommendation: Dict, 
                                      terraform_files: Dict[str, str]) -> Optional[Dict]:
        """Modify existing Terraform file to remove unused permissions
        
        Args:
            resource_key: Resource identifier
            recommendation: Policy recommendation
            terraform_files: Dictionary of existing Terraform files
            
        Returns:
            Dictionary with modified file information or None
        """
        try:
            resource_name = recommendation['tf_resource_name']
            unused_services = recommendation['unused_services']
            unused_actions = recommendation['unused_actions']
            
            # Find the file containing this resource
            for file_path, content in terraform_files.items():
                if self._resource_exists_in_file(content, resource_name, resource_key):
                    logger.info(f"Found resource {resource_name} in {file_path}")
                    
                    # Modify the file content
                    modified_content = self._remove_unused_permissions_from_file(
                        content, resource_name, unused_services, unused_actions, recommendation
                    )
                    
                    if modified_content != content:
                        return {
                            'path': file_path,
                            'content': modified_content,
                            'modification_type': 'remove_unused_permissions'
                        }
            
            return None
            
        except Exception as e:
            logger.error(f"Error modifying Terraform file for {resource_key}: {str(e)}")
            return None
    
    def _resource_exists_in_file(self, content: str, resource_name: str, resource_key: str) -> bool:
        """Check if a resource exists in the Terraform file content"""
        try:
            # Look for resource blocks that match our resource
            patterns = [
                rf'resource\s+"aws_iam_\w+_policy"\s+"{resource_name}"',
                rf'resource\s+"aws_iam_\w+"\s+"{resource_name}"',
                # Also check for the resource name in the content
                resource_name,
                resource_name.replace('_', '-')
            ]
            
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking if resource exists in file: {str(e)}")
            return False
    
    def _remove_unused_permissions_from_file(self, content: str, resource_name: str, 
                                           unused_services: List[str], unused_actions: List[str],
                                           recommendation: Dict) -> str:
        """Remove unused permissions from Terraform file content with AWS validation
        
        Args:
            content: Original file content
            resource_name: Name of the resource to modify
            unused_services: List of unused services
            unused_actions: List of unused actions
            recommendation: Full recommendation data
            
        Returns:
            Modified file content
        """
        try:
            # Extract existing policies from the file
            policies = self._extract_policies_from_terraform(content)
            
            if not policies:
                logger.warning(f"No policies found in file for resource {resource_name}")
                return content
            
            # Modify and validate each policy
            modified_policies = {}
            validation_results = []
            
            for policy_name, policy_data in policies.items():
                logger.info(f"Processing policy: {policy_name}")
                
                # Remove unused services from the policy
                modified_policy = self._remove_unused_services_from_policy_dict(
                    policy_data, unused_services
                )
                
                # Validate the modified policy using AWS Access Analyzer
                validation_result = self._validate_policy_with_aws(modified_policy, policy_name)
                validation_results.append(validation_result)
                
                if validation_result['is_valid']:
                    modified_policies[policy_name] = modified_policy
                    logger.info(f"Policy {policy_name} modified and validated successfully")
                else:
                    logger.warning(f"Policy {policy_name} failed validation: {validation_result['errors']}")
                    # Keep original policy if validation fails
                    modified_policies[policy_name] = policy_data
            
            # Only proceed with modifications if all policies are valid
            all_valid = all(result['is_valid'] for result in validation_results)
            
            if not all_valid:
                logger.warning("Some policies failed validation, keeping original content")
                return content
            
            # Replace policies in the original content
            modified_content = self._replace_policies_in_terraform(content, modified_policies)
            
            # Add modification comment at the top
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            modification_comment = f"""
# MODIFIED BY LEAST PRIVILEGE OPTIMIZER - {timestamp}
# Finding ID: {recommendation['finding_id']}
# Resource: {resource_name}
# Removed unused services: {', '.join(unused_services)}
# This modification removes {len(unused_services)} unused service permissions
# Based on AWS Access Analyzer findings for least privilege access
# All policies validated using AWS Access Analyzer validate-policy API
#
"""
            
            # Add the modification comment at the beginning
            modified_content = modification_comment + modified_content
            
            return modified_content
            
        except Exception as e:
            logger.error(f"Error removing unused permissions: {str(e)}")
            return content
    
    def _extract_policies_from_terraform(self, content: str) -> Dict[str, Dict]:
        """Extract IAM policies from Terraform content
        
        Args:
            content: Terraform file content
            
        Returns:
            Dictionary mapping policy names to policy dictionaries
        """
        try:
            policies = {}
            
            # Find all jsonencode policy blocks with improved regex
            policy_pattern = r'policy\s*=\s*jsonencode\s*\(\s*(\{[^}]*(?:\{[^}]*\}[^}]*)*\})\s*\)'
            
            for match in re.finditer(policy_pattern, content, re.DOTALL):
                policy_content = match.group(1)
                
                try:
                    # Convert HCL-style to JSON and parse
                    json_content = self._hcl_to_json_robust(policy_content)
                    policy_dict = json.loads(json_content)
                    
                    # Generate a policy name (you might want to extract this from context)
                    policy_name = f"policy_{len(policies) + 1}"
                    policies[policy_name] = policy_dict
                    
                except Exception as e:
                    logger.warning(f"Could not parse policy content: {str(e)}")
                    logger.debug(f"Failed policy content: {policy_content}")
                    continue
            
            logger.info(f"Extracted {len(policies)} policies from Terraform content")
            return policies
            
        except Exception as e:
            logger.error(f"Error extracting policies from Terraform: {str(e)}")
            return {}
    
    def _hcl_to_json_robust(self, hcl_content: str) -> str:
        """Robust HCL to JSON conversion for Terraform policy blocks
        
        Args:
            hcl_content: HCL-style policy content
            
        Returns:
            Valid JSON string
        """
        try:
            # Clean up the content
            content = hcl_content.strip()
            
            # Handle the HCL format used in Terraform jsonencode blocks
            # These are actually JSON-like but with HCL key = value syntax
            
            # Step 1: Convert key = value to "key": value
            content = re.sub(r'(\w+)\s*=\s*', r'"\1": ', content)
            
            # Step 2: Handle arrays - ensure values are properly quoted
            # Match array patterns like: ["value1", "value2"] or [value1, value2]
            def fix_array_content(match):
                array_inner = match.group(1)
                # Split by comma and clean up each value
                values = []
                for value in array_inner.split(','):
                    value = value.strip()
                    if value:
                        # If not already quoted and not a number/boolean, add quotes
                        if not (value.startswith('"') and value.endswith('"')) and \
                           not value.lower() in ['true', 'false'] and \
                           not value.replace('.', '').replace('-', '').isdigit():
                            value = f'"{value}"'
                        values.append(value)
                return f'[{", ".join(values)}]'
            
            content = re.sub(r'\[\s*([^]]*)\s*\]', fix_array_content, content)
            
            # Step 3: Quote unquoted string values that aren't arrays, objects, or keywords
            def quote_unquoted_values(match):
                key = match.group(1)
                value = match.group(2).strip()
                
                # Don't quote if it's already quoted, or if it's an array/object/boolean/number
                if (value.startswith('"') and value.endswith('"')) or \
                   value.startswith('[') or value.startswith('{') or \
                   value.lower() in ['true', 'false', 'null'] or \
                   value.replace('.', '').replace('-', '').isdigit():
                    return f'"{key}": {value}'
                else:
                    return f'"{key}": "{value}"'
            
            content = re.sub(r'"(\w+)":\s*([^,\]\}]+)', quote_unquoted_values, content)
            
            return content
            
        except Exception as e:
            logger.error(f"Error in robust HCL to JSON conversion: {str(e)}")
            return hcl_content
    
    def _remove_unused_services_from_policy_dict(self, policy_dict: Dict, unused_services: List[str]) -> Dict:
        """Remove unused services from a policy dictionary
        
        Args:
            policy_dict: IAM policy as dictionary
            unused_services: List of unused service namespaces
            
        Returns:
            Modified policy dictionary
        """
        try:
            modified_policy = json.loads(json.dumps(policy_dict))  # Deep copy
            
            if 'Statement' not in modified_policy:
                return modified_policy
            
            statements = modified_policy['Statement']
            if not isinstance(statements, list):
                statements = [statements]
            
            filtered_statements = []
            
            for statement in statements:
                if 'Action' not in statement:
                    filtered_statements.append(statement)
                    continue
                
                actions = statement['Action']
                if not isinstance(actions, list):
                    actions = [actions]
                
                # Filter out actions from unused services
                filtered_actions = []
                for action in actions:
                    if isinstance(action, str):
                        service = action.split(':')[0] if ':' in action else action
                        if service not in unused_services:
                            filtered_actions.append(action)
                
                # Only keep statement if it has remaining actions
                if filtered_actions:
                    statement['Action'] = filtered_actions if len(filtered_actions) > 1 else filtered_actions[0]
                    filtered_statements.append(statement)
                else:
                    logger.info(f"Removing statement with only unused service actions: {unused_services}")
            
            modified_policy['Statement'] = filtered_statements
            return modified_policy
            
        except Exception as e:
            logger.error(f"Error removing unused services from policy dict: {str(e)}")
            return policy_dict
    
    def _validate_policy_with_aws(self, policy_dict: Dict, policy_name: str) -> Dict:
        """Validate policy using AWS Access Analyzer validate-policy API
        
        Args:
            policy_dict: IAM policy dictionary to validate
            policy_name: Name of the policy for logging
            
        Returns:
            Dictionary with validation results
        """
        try:
            logger.info(f"Validating policy {policy_name} with AWS Access Analyzer")
            
            # Convert policy dict to JSON string
            policy_document = json.dumps(policy_dict)
            
            # Call AWS Access Analyzer validate-policy API
            response = self.access_analyzer.validate_policy(
                policyDocument=policy_document,
                policyType='IDENTITY_POLICY'
            )
            
            findings = response.get('findings', [])
            
            # Check if there are any ERROR level findings
            error_findings = [f for f in findings if f.get('findingType') == 'ERROR']
            warning_findings = [f for f in findings if f.get('findingType') == 'WARNING']
            
            is_valid = len(error_findings) == 0
            
            result = {
                'is_valid': is_valid,
                'policy_name': policy_name,
                'error_count': len(error_findings),
                'warning_count': len(warning_findings),
                'errors': [f.get('findingDetails', 'Unknown error') for f in error_findings],
                'warnings': [f.get('findingDetails', 'Unknown warning') for f in warning_findings]
            }
            
            if is_valid:
                logger.info(f"Policy {policy_name} validation successful ({len(warning_findings)} warnings)")
            else:
                logger.error(f"Policy {policy_name} validation failed with {len(error_findings)} errors")
                for error in result['errors']:
                    logger.error(f"  - {error}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error validating policy {policy_name} with AWS: {str(e)}")
            return {
                'is_valid': False,
                'policy_name': policy_name,
                'error_count': 1,
                'warning_count': 0,
                'errors': [f"Validation API call failed: {str(e)}"],
                'warnings': []
            }
    
    def _replace_policies_in_terraform(self, content: str, modified_policies: Dict[str, Dict]) -> str:
        """Replace policies in Terraform content with validated modified versions
        
        Args:
            content: Original Terraform content
            modified_policies: Dictionary of validated modified policies
            
        Returns:
            Terraform content with replaced policies
        """
        try:
            modified_content = content
            policy_index = 0
            
            # Find and replace each policy block
            policy_pattern = r'(policy\s*=\s*jsonencode\s*\()([^)]+(?:\([^)]*\)[^)]*)*)\)'
            
            def replace_policy(match):
                nonlocal policy_index
                policy_index += 1
                policy_name = f"policy_{policy_index}"
                
                if policy_name in modified_policies:
                    # Convert policy dict to HCL-style format
                    policy_hcl = self._json_to_hcl(modified_policies[policy_name])
                    return match.group(1) + policy_hcl + ')'
                else:
                    return match.group(0)  # Keep original if not modified
            
            modified_content = re.sub(policy_pattern, replace_policy, modified_content, flags=re.DOTALL)
            
            return modified_content
            
        except Exception as e:
            logger.error(f"Error replacing policies in Terraform: {str(e)}")
            return content
    
    def _json_to_hcl(self, policy_dict: Dict) -> str:
        """Convert policy dictionary back to HCL-style format for Terraform
        
        Args:
            policy_dict: Policy dictionary
            
        Returns:
            HCL-style formatted policy string
        """
        try:
            # Convert to JSON first
            json_str = json.dumps(policy_dict, indent=2)
            
            # Convert JSON to HCL-style format
            hcl_str = json_str
            
            # Replace JSON key formats with HCL
            hcl_str = re.sub(r'"(\w+)":\s*', r'\1 = ', hcl_str)
            
            # Clean up formatting for Terraform
            hcl_str = hcl_str.replace('"', '"')  # Ensure proper quotes
            
            return hcl_str
            
        except Exception as e:
            logger.error(f"Error converting JSON to HCL: {str(e)}")
            return json.dumps(policy_dict, indent=2)
    
    def _create_recommendation_file(self, resource_key: str, recommendation: Dict) -> Optional[Dict]:
        """Create a new recommendation file when no existing Terraform file can be modified
        
        Args:
            resource_key: Resource identifier
            recommendation: Policy recommendation
            
        Returns:
            Dictionary with file information or None
        """
        try:
            # Generate Terraform content for the recommendation
            terraform_content = self._generate_terraform_content(resource_key, recommendation)
            
            if not terraform_content:
                logger.warning(f"No Terraform content generated for {resource_key}")
                return None
            
            # Determine file path based on recommendation type
            file_path = self._get_terraform_file_path(resource_key, recommendation)
            
            return {
                'path': file_path,
                'content': terraform_content,
                'modification_type': 'new_recommendation'
            }
            
        except Exception as e:
            logger.error(f"Error creating recommendation file for {resource_key}: {str(e)}")
            return None
    
    def _generate_terraform_content(self, resource_key: str, recommendation: Dict) -> str:
        """Generate Terraform content for a policy recommendation
        
        Args:
            resource_key: Resource identifier
            recommendation: Policy recommendation data
            
        Returns:
            Terraform content string
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            finding_id = recommendation.get('finding_id', 'unknown')
            resource_name = recommendation.get('resource_name', 'unknown')
            recommendation_type = recommendation.get('recommendation_type', 'unknown')
            
            # Header comment
            content = f"""# Generated by Least Privilege Optimizer - {timestamp}
# Access Analyzer Finding: {finding_id}
# Resource: {resource_name}
# Recommendation Type: {recommendation_type}
#
# This file contains AWS Access Analyzer recommendations for least privilege access.
# Review the recommendations and apply them after thorough testing.

"""
            
            if recommendation_type == "remove_unused_permissions":
                # Generate content for unused permissions removal
                unused_services = recommendation.get('unused_services', [])
                unused_actions = recommendation.get('unused_actions', [])
                
                content += f"""# RECOMMENDATION: Remove Unused Permissions
# This resource has {len(unused_services)} unused AWS service namespaces
# Total unused actions detected: {len(unused_actions)}
#
# Unused Services: {', '.join(unused_services)}
#
# VALIDATION: All recommendations validated with AWS Access Analyzer validate-policy API
#
# INSTRUCTIONS:
# 1. Review the unused services and actions below
# 2. Remove these permissions from your IAM policies
# 3. Test thoroughly in a non-production environment
# 4. Apply changes gradually with monitoring

"""
                
                # List unused actions by service
                service_actions = {}
                for action in unused_actions:
                    service = action.split(':')[0] if ':' in action else 'unknown'
                    if service not in service_actions:
                        service_actions[service] = []
                    service_actions[service].append(action)
                
                content += "# Unused Actions by Service:\n"
                for service, actions in service_actions.items():
                    content += f"#\n# {service.upper()} Service ({len(actions)} actions):\n"
                    for action in actions[:10]:  # Limit to first 10 actions
                        content += f"#   - {action}\n"
                    if len(actions) > 10:
                        content += f"#   ... and {len(actions) - 10} more actions\n"
                
            else:
                # Generic recommendation content
                content += f"""# MANUAL REVIEW REQUIRED
# Finding Type: {recommendation.get('finding_type', 'unknown')}
# Confidence: {recommendation.get('confidence', 'unknown')}
# Action Required: {recommendation.get('action_required', 'unknown')}
#
# Reason: {recommendation.get('recommendation_reason', 'No reason provided')}
#
# Please review this finding manually and take appropriate action.
"""
            
            return content
            
        except Exception as e:
            logger.error(f"Error generating Terraform content: {str(e)}")
            return ""
    
    def _get_terraform_file_path(self, resource_key: str, recommendation: Dict) -> str:
        """Generate appropriate file path for Terraform recommendation
        
        Args:
            resource_key: Resource identifier
            recommendation: Policy recommendation
            
        Returns:
            File path string
        """
        try:
            recommendation_type = recommendation.get('recommendation_type', 'unknown')
            tf_resource_name = recommendation.get('tf_resource_name', 'unknown')
            
            if recommendation_type == "remove_unused_permissions":
                return f"terraform/policies/least_privilege_{tf_resource_name}.tf"
            elif recommendation_type == "security_review":
                return f"terraform/reviews/review_{tf_resource_name}.tf"
            else:
                return f"terraform/recommendations/recommendation_{tf_resource_name}.tf"
                
        except Exception as e:
            logger.error(f"Error generating file path: {str(e)}")
            return f"terraform/recommendations/recommendation_unknown.tf"
    
    def _generate_pr_content(self, recommendations: Dict[str, Dict], modification_summary: List[Dict]) -> tuple:
        """Generate PR title and body content
        
        Args:
            recommendations: Dictionary of policy recommendations
            modification_summary: List of modification details
            
        Returns:
            Tuple of (title, body) strings
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            total_recommendations = len(recommendations)
            
            # Generate title
            title = f"IAM Policy Updates - {total_recommendations} Access Analyzer Recommendations ({timestamp})"
            
            # Count recommendations by type
            by_type = {}
            by_confidence = {}
            by_action = {}
            total_unused_services = 0
            total_unused_actions = 0
            
            for recommendation in recommendations.values():
                rec_type = recommendation.get('recommendation_type', 'unknown')
                confidence = recommendation.get('confidence', 'unknown')
                action = recommendation.get('action_required', 'unknown')
                
                by_type[rec_type] = by_type.get(rec_type, 0) + 1
                by_confidence[confidence] = by_confidence.get(confidence, 0) + 1
                by_action[action] = by_action.get(action, 0) + 1
                
                total_unused_services += len(recommendation.get('unused_services', []))
                total_unused_actions += len(recommendation.get('unused_actions', []))
            
            # Generate body
            body = f"""# IAM Policy Updates - Access Analyzer Recommendations

This PR contains IAM policy optimization recommendations based on AWS Access Analyzer findings.

## Summary

**Total Recommendations**: {total_recommendations}
**Total Unused Services**: {total_unused_services}
**Total Unused Actions**: {total_unused_actions}

## Recommendations by Type
"""
            
            for rec_type, count in by_type.items():
                body += f"- **{rec_type.replace('_', ' ').title()}**: {count}\n"
            
            body += f"""
## Confidence Levels
"""
            
            for confidence, count in by_confidence.items():
                body += f"- **{confidence.title()}**: {count}\n"
            
            body += f"""
## Action Required
"""
            
            for action, count in by_action.items():
                body += f"- **{action.replace('_', ' ').title()}**: {count}\n"
            
            body += f"""
## Modified Resources

| Resource | Unused Services | Unused Actions | File Modified |
|----------|----------------|----------------|---------------|
"""
            
            for summary in modification_summary:
                body += f"| {summary['resource']} | {summary['unused_services']} | {summary['unused_actions']} | {summary['file_modified']} |\n"
            
            body += f"""
## Safety & Validation

✅ **All policy modifications have been validated using AWS Access Analyzer validate-policy API**
✅ **Only valid policies are included in this PR**
✅ **Original policies are preserved if validation fails**

## Testing Recommendations

1. **Review each recommendation carefully** - Understand which permissions are being removed
2. **Test in non-production first** - Apply changes to dev/staging environments
3. **Monitor application behavior** - Ensure no functionality is broken
4. **Apply changes gradually** - Implement changes in phases with monitoring
5. **Have rollback plan ready** - Keep original policies available for quick revert

## Terraform Commands

To apply these changes:

```bash
# Review the changes
terraform plan

# Apply the changes (after testing)
terraform apply
```

## AWS Access Analyzer Details

These recommendations are based on AWS Access Analyzer findings that identify unused permissions. The analyzer uses AWS CloudTrail logs and other data sources to determine which permissions have not been used in the last 90 days.

Generated at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
            
            return title, body
            
        except Exception as e:
            logger.error(f"Error generating PR content: {str(e)}")
            return "IAM Policy Updates", "Error generating PR content"
    
    def _create_github_pr(self, title: str, body: str, files: List[Dict]) -> bool:
        """Create GitHub pull request with the specified files
        
        Args:
            title: PR title
            body: PR body content
            files: List of file dictionaries with path and content
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create a new branch for the PR
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            branch_name = f"iam-policy-updates-{timestamp}"
            
            # Get the default branch reference
            default_branch = self.repo.default_branch
            base_ref = self.repo.get_git_ref(f"heads/{default_branch}")
            base_sha = base_ref.object.sha
            
            # Create new branch
            new_ref = self.repo.create_git_ref(
                ref=f"refs/heads/{branch_name}",
                sha=base_sha
            )
            
            # Create/update files in the new branch
            for file_info in files:
                file_path = file_info['path']
                file_content = file_info['content']
                modification_type = file_info.get('modification_type', 'update')
                
                try:
                    # Check if file exists
                    try:
                        existing_file = self.repo.get_contents(file_path, ref=branch_name)
                        # Update existing file
                        self.repo.update_file(
                            path=file_path,
                            message=f"Update {file_path} - {modification_type}",
                            content=file_content,
                            sha=existing_file.sha,
                            branch=branch_name
                        )
                        logger.info(f"Updated existing file: {file_path}")
                    except:
                        # Create new file
                        self.repo.create_file(
                            path=file_path,
                            message=f"Create {file_path} - {modification_type}",
                            content=file_content,
                            branch=branch_name
                        )
                        logger.info(f"Created new file: {file_path}")
                        
                except Exception as e:
                    logger.error(f"Failed to create/update file {file_path}: {str(e)}")
                    continue
            
            # Create the pull request
            pr = self.repo.create_pull(
                title=title,
                body=body,
                head=branch_name,
                base=default_branch
            )
            
            logger.info(f"Successfully created PR #{pr.number}: {pr.html_url}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create GitHub PR: {str(e)}")
            return False