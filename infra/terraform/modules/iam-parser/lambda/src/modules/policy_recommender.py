from typing import Dict, List, Optional, Union
import json
from aws_lambda_powertools import Logger
from github import Github, Auth
from botocore.exceptions import ClientError

# Import the new types for better compatibility
try:
    from .iam_analyzer import IAMResource, ResourceType
except ImportError:
    # Fallback for when types aren't available
    IAMResource = None
    ResourceType = None

logger = Logger(service="PolicyRecommender")

class PolicyRecommender:
    """Handles policy recommendations and terraform updates based on analyzer findings"""
    
    def __init__(self, github_token: str, repo_name: str):
        """Initialize PolicyRecommender
        
        Args:
            github_token: GitHub personal access token
            repo_name: Repository name in format 'owner/repo'
        """
        self.github_token = github_token
        self.repo_name = repo_name
        logger.info(f"Initialized PolicyRecommender for repo: {repo_name}")
    
    def _extract_resource_arn(self, finding: Dict) -> str:
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
        
    def _extract_resource_policy(self, finding: Dict) -> Dict:
        """
        Safely extract resource policy from finding, handling different data structures
        
        Args:
            finding: Access Analyzer finding
            
        Returns:
            Resource policy dictionary or empty dict if not found
        """
        finding_id = finding.get('id', 'unknown')
        try:
            resource = finding.get('resource')
            
            if resource is None:
                logger.debug(f"Finding {finding_id}: No resource field present")
                return {}
            
            logger.debug(f"Finding {finding_id}: Resource field type: {type(resource)}")
            
            # Handle case where resource is a dictionary (expected)
            if isinstance(resource, dict):
                policy = resource.get('policy')
                if policy is None:
                    logger.debug(f"Finding {finding_id}: Resource is dict but no policy field present. Resource keys: {list(resource.keys())}")
                    return {}
                elif isinstance(policy, dict):
                    logger.debug(f"Finding {finding_id}: Found policy with {len(policy.get('Statement', []))} statements")
                    return policy
                else:
                    logger.warning(f"Finding {finding_id}: Policy field exists but is not a dict: {type(policy)}")
                    return {}
            
            # Handle case where resource is a string (the ARN itself) - no policy available
            elif isinstance(resource, str):
                logger.debug(f"Finding {finding_id}: Resource is string (ARN): {resource}, no policy available")
                return {}
            
            # Handle unexpected resource type
            else:
                logger.warning(f"Finding {finding_id}: Unexpected resource type: {type(resource)}, value: {resource}")
                return {}
                
        except Exception as e:
            logger.error(f"Finding {finding_id}: Error extracting resource policy: {str(e)}")
            return {}

    def _analyze_finding_structure(self, finding: Dict) -> Dict:
        """
        Analyze the structure of a finding to understand what data is available
        
        Args:
            finding: Access Analyzer finding
            
        Returns:
            Dictionary with analysis results
        """
        finding_id = finding.get('id', 'unknown')
        analysis = {
            'finding_id': finding_id,
            'finding_type': finding.get('findingType', 'unknown'),
            'has_resource_field': 'resource' in finding,
            'resource_type': type(finding.get('resource')).__name__ if 'resource' in finding else 'missing',
            'has_analyzed_policy': 'analyzedPolicy' in finding,
            'has_finding_details': 'findingDetails' in finding,
            'resource_keys': [],
            'finding_detail_keys': []
        }
        
        # Analyze resource structure
        resource = finding.get('resource')
        if isinstance(resource, dict):
            analysis['resource_keys'] = list(resource.keys())
            analysis['has_policy_in_resource'] = 'policy' in resource
            analysis['has_arn_in_resource'] = 'arn' in resource
        elif isinstance(resource, str):
            analysis['resource_as_string'] = resource
        
        # Analyze finding details structure
        finding_details = finding.get('findingDetails')
        if isinstance(finding_details, dict):
            analysis['finding_detail_keys'] = list(finding_details.keys())
            analysis['has_unused_actions'] = 'unusedActions' in finding_details
            analysis['unused_actions_count'] = len(finding_details.get('unusedActions', []))
        
        return analysis

    def _generate_recommendation_from_analyzed_policy(self, finding: Dict, resource: Dict) -> Optional[Dict]:
        """
        Generate recommendation when we have analyzedPolicy but no current policy
        
        Args:
            finding: Access Analyzer finding
            resource: Resource details
            
        Returns:
            Dictionary with recommended policy changes or None
        """
        finding_id = finding.get('id', 'unknown')
        analyzed_policy = finding.get('analyzedPolicy', {})
        
        if not analyzed_policy:
            logger.debug(f"Finding {finding_id}: No analyzedPolicy available")
            return None
            
        logger.info(f"Finding {finding_id}: Creating recommendation from analyzedPolicy (least privilege suggestion)")
        
        # This represents a policy that Access Analyzer suggests based on actual usage
        return {
            'current_policy': {},  # No current policy found
            'recommended_policy': analyzed_policy,
            'resource_name': resource['ResourceName'],
            'resource_type': resource['ResourceType'],
            'finding_id': finding_id,
            'finding_type': finding.get('findingType'),
            'tf_resource_name': resource.get('tf_resource_name'),
            'unused_actions': [],  # Not applicable when we don't have current policy
            'recommendation_reason': f"Access Analyzer suggests this policy based on actual usage patterns for {finding.get('findingType', 'unknown')} finding",
            'recommendation_type': 'least_privilege_suggestion',
            'confidence': 'high'  # Access Analyzer suggestions are typically high confidence
        }

    def _generate_recommendation_from_finding_details(self, finding: Dict, resource: Dict) -> Optional[Dict]:
        """
        Generate recommendation based on finding details when no policies are available
        
        Args:
            finding: Access Analyzer finding
            resource: Resource details
            
        Returns:
            Dictionary with recommended actions or None
        """
        finding_id = finding.get('id', 'unknown')
        finding_type = finding.get('findingType', 'unknown')
        finding_details = finding.get('findingDetails', {})
        
        if not finding_details:
            logger.debug(f"Finding {finding_id}: No findingDetails available")
            return None
            
        logger.info(f"Finding {finding_id}: Creating recommendation from finding details for {finding_type}")
        
        # Generate different recommendations based on finding type
        if finding_type == 'EXTERNAL_ACCESS':
            return {
                'current_policy': {},
                'recommended_policy': {},
                'resource_name': resource['ResourceName'],
                'resource_type': resource['ResourceType'],
                'finding_id': finding_id,
                'finding_type': finding_type,
                'tf_resource_name': resource.get('tf_resource_name'),
                'unused_actions': [],
                'recommendation_reason': "External access detected - review resource configuration and restrict access if unnecessary",
                'recommendation_type': 'security_review',
                'confidence': 'medium',
                'action_required': 'manual_review',
                'finding_details': finding_details
            }
        elif finding_type == 'UNUSED_IAM_ROLE':
            return {
                'current_policy': {},
                'recommended_policy': {},
                'resource_name': resource['ResourceName'],
                'resource_type': resource['ResourceType'],
                'finding_id': finding_id,
                'finding_type': finding_type,
                'tf_resource_name': resource.get('tf_resource_name'),
                'unused_actions': [],
                'recommendation_reason': "IAM role appears to be unused - consider removing if not needed",
                'recommendation_type': 'removal_candidate',
                'confidence': 'medium',
                'action_required': 'review_for_removal',
                'finding_details': finding_details
            }
        elif finding_type == 'UNUSED_IAM_USER_CREDENTIALS':
            return {
                'current_policy': {},
                'recommended_policy': {},
                'resource_name': resource['ResourceName'],
                'resource_type': resource['ResourceType'],
                'finding_id': finding_id,
                'finding_type': finding_type,
                'tf_resource_name': resource.get('tf_resource_name'),
                'unused_actions': [],
                'recommendation_reason': "IAM user credentials appear to be unused - consider removing or rotating",
                'recommendation_type': 'credential_review',
                'confidence': 'medium',
                'action_required': 'credential_management',
                'finding_details': finding_details
            }
        else:
            # Generic recommendation for unknown finding types
            return {
                'current_policy': {},
                'recommended_policy': {},
                'resource_name': resource['ResourceName'],
                'resource_type': resource['ResourceType'],
                'finding_id': finding_id,
                'finding_type': finding_type,
                'tf_resource_name': resource.get('tf_resource_name'),
                'unused_actions': [],
                'recommendation_reason': f"Access Analyzer finding of type {finding_type} requires review",
                'recommendation_type': 'general_review',
                'confidence': 'low',
                'action_required': 'manual_analysis',
                'finding_details': finding_details
            }

    def process_findings(self, findings: List[Dict], resources: Union[List[Dict], List]) -> Dict[str, Dict]:
        """Process analyzer findings and generate policy recommendations
        
        Args:
            findings: List of IAM Access Analyzer findings
            resources: List of resources (either dicts or IAMResource objects)
            
        Returns:
            Dictionary mapping resource names to recommended policy changes
        """
        logger.info(f"Processing {len(findings)} findings for {len(resources)} resources")
        recommendations = {}
        
        # Create lookup for resources by ARN - handle both dict and IAMResource objects
        resource_lookup = {}
        for resource in resources:
            if hasattr(resource, 'arn'):  # IAMResource object
                resource_lookup[resource.arn] = {
                    'ResourceARN': resource.arn,
                    'ResourceType': resource.resource_type.value,
                    'ResourceName': resource.name,
                    'tf_resource_name': resource.name.replace('-', '_')
                }
            else:  # Dictionary format
                resource_lookup[resource['ResourceARN']] = resource
        
        logger.debug(f"Created resource lookup for {len(resource_lookup)} resources")
        
        processed_findings = 0
        for finding in findings:
            # Use the safe extraction method
            resource_arn = self._extract_resource_arn(finding)
            if resource_arn == 'unknown':
                logger.warning(f"Finding {finding.get('id', 'unknown')} missing resource ARN, skipping")
                continue
                
            if resource_arn not in resource_lookup:
                logger.debug(f"Resource {resource_arn} not in our target list, skipping")
                continue
                
            resource = resource_lookup[resource_arn]
            tf_resource_type = self._get_tf_resource_type(resource['ResourceType'])
            
            if not tf_resource_type:
                logger.warning(f"Unsupported resource type: {resource['ResourceType']}")
                continue
            
            # Generate policy recommendation
            recommendation = self._generate_recommendation(finding, resource)
            if recommendation:
                key = f"{tf_resource_type}.{resource['ResourceName']}"
                recommendations[key] = recommendation
                processed_findings += 1
                logger.debug(f"Generated recommendation for {key}")
                
        logger.info(f"Generated {len(recommendations)} recommendations from {processed_findings} processed findings")
        return recommendations
    
    def _get_tf_resource_type(self, aws_resource_type: str) -> Optional[str]:
        """Convert AWS resource type to Terraform resource type"""
        mapping = {
            'AWS::IAM::Role': 'aws_iam_role',
            'AWS::IAM::User': 'aws_iam_user',
            'AWS::IAM::Group': 'aws_iam_group',
            'AWS::IAM::Policy': 'aws_iam_policy'
        }
        return mapping.get(aws_resource_type)
    
    def _generate_recommendation(self, finding: Dict, resource: Dict) -> Optional[Dict]:
        """Generate policy recommendation for a resource based on finding
        
        Args:
            finding: IAM Access Analyzer finding
            resource: Resource details
            
        Returns:
            Dictionary with recommended policy changes
        """
        finding_id = finding.get('id', 'unknown')
        
        try:
            logger.debug(f"Finding {finding_id}: Starting recommendation generation")
            
            # First, analyze the finding structure for better logging
            analysis = self._analyze_finding_structure(finding)
            logger.info(f"Finding {finding_id}: Structure analysis: {analysis}")
            
            # Extract current and recommended permissions using safe method
            current_policy = self._extract_resource_policy(finding)
            analyzed_policy = finding.get('analyzedPolicy', {})
            
            logger.debug(f"Finding {finding_id}: Current policy found: {bool(current_policy)}")
            logger.debug(f"Finding {finding_id}: Analyzed policy found: {bool(analyzed_policy)}")
            
            # Strategy 1: We have both current and analyzed policies (traditional case)
            if current_policy and analyzed_policy:
                logger.info(f"Finding {finding_id}: Using traditional policy comparison approach")
                return self._generate_traditional_recommendation(finding, resource, current_policy, analyzed_policy)
            
            # Strategy 2: We have analyzed policy but no current policy
            elif analyzed_policy and not current_policy:
                logger.info(f"Finding {finding_id}: Using analyzed policy as least privilege suggestion")
                return self._generate_recommendation_from_analyzed_policy(finding, resource)
            
            # Strategy 3: No policies but UNUSED_ACCESS with finding details
            elif finding.get('findingType') == 'UNUSED_ACCESS' and finding.get('findingDetails'):
                logger.info(f"Finding {finding_id}: Using finding details for UNUSED_ACCESS recommendation")
                finding_details = finding.get('findingDetails', {})
                unused_actions = finding_details.get('unusedActions', [])
                
                if unused_actions:
                    # We know what actions are unused, even without the full current policy
                    return {
                        'current_policy': {},
                        'recommended_policy': {},
                        'resource_name': resource['ResourceName'],
                        'resource_type': resource['ResourceType'],
                        'finding_id': finding_id,
                        'finding_type': 'UNUSED_ACCESS',
                        'tf_resource_name': resource.get('tf_resource_name'),
                        'unused_actions': unused_actions,
                        'recommendation_reason': f"Found {len(unused_actions)} unused permissions that can be removed for least privilege",
                        'recommendation_type': 'remove_unused_permissions',
                        'confidence': 'high',
                        'action_required': 'policy_optimization'
                    }
            
            # Strategy 4: Use finding details for other finding types
            elif finding.get('findingDetails'):
                logger.info(f"Finding {finding_id}: Using finding details for general recommendation")
                return self._generate_recommendation_from_finding_details(finding, resource)
            
            # Strategy 5: Last resort - create minimal recommendation
            else:
                logger.warning(f"Finding {finding_id}: No usable policy or detail information found, creating minimal recommendation")
                return {
                    'current_policy': {},
                    'recommended_policy': {},
                    'resource_name': resource['ResourceName'],
                    'resource_type': resource['ResourceType'],
                    'finding_id': finding_id,
                    'finding_type': finding.get('findingType', 'unknown'),
                    'tf_resource_name': resource.get('tf_resource_name'),
                    'unused_actions': [],
                    'recommendation_reason': f"Access Analyzer finding requires manual review - insufficient data for automated recommendation",
                    'recommendation_type': 'manual_review_required',
                    'confidence': 'low',
                    'action_required': 'manual_analysis',
                    'raw_finding': finding  # Include full finding for manual analysis
                }
            
        except Exception as e:
            logger.error(f"Finding {finding_id}: Error generating recommendation: {str(e)}")
            logger.error(f"Finding {finding_id}: Raw finding data: {json.dumps(finding, indent=2, default=str)}")
            return None

    def _generate_traditional_recommendation(self, finding: Dict, resource: Dict, current_policy: Dict, analyzed_policy: Dict) -> Dict:
        """Generate recommendation when we have both current and analyzed policies"""
        finding_id = finding.get('id', 'unknown')
        
        # For UNUSED_ACCESS findings, create a minimal policy by removing unused actions
        if finding.get('findingType') == 'UNUSED_ACCESS':
            finding_details = finding.get('findingDetails', {})
            unused_actions = finding_details.get('unusedActions', [])
            
            if unused_actions:
                # Create a recommended policy by removing unused actions
                minimal_policy = self._create_minimal_policy(current_policy, unused_actions)
                analyzed_policy = minimal_policy or analyzed_policy
        
        return {
            'current_policy': current_policy,
            'recommended_policy': analyzed_policy,
            'resource_name': resource['ResourceName'],
            'resource_type': resource['ResourceType'],
            'finding_id': finding_id,
            'finding_type': finding.get('findingType'),
            'tf_resource_name': resource.get('tf_resource_name'),
            'unused_actions': finding.get('findingDetails', {}).get('unusedActions', []),
            'recommendation_reason': self._get_recommendation_reason(finding),
            'recommendation_type': 'policy_optimization',
            'confidence': 'high'
        }

    def _create_minimal_policy(self, current_policy: Dict, unused_actions: List[str]) -> Dict:
        """Create a minimal policy by removing unused actions"""
        try:
            minimal_policy = {
                "Version": current_policy.get("Version", "2012-10-17"),
                "Statement": []
            }
            
            for statement in current_policy.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    # Keep non-Allow statements as-is
                    minimal_policy["Statement"].append(statement)
                    continue
                
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Remove unused actions
                used_actions = [action for action in actions if action not in unused_actions]
                
                if used_actions:
                    new_statement = statement.copy()
                    new_statement["Action"] = used_actions if len(used_actions) > 1 else used_actions[0]
                    minimal_policy["Statement"].append(new_statement)
            
            return minimal_policy
            
        except Exception as e:
            logger.error(f"Error creating minimal policy: {str(e)}")
            return {}
    
    def _get_recommendation_reason(self, finding: Dict) -> str:
        """Generate a human-readable reason for the recommendation"""
        finding_type = finding.get('findingType', 'unknown')
        
        if finding_type == 'UNUSED_ACCESS':
            unused_count = len(finding.get('findingDetails', {}).get('unusedActions', []))
            return f"Found {unused_count} unused permissions that can be removed for least privilege"
        elif finding_type == 'EXTERNAL_ACCESS':
            return "External access detected - review and restrict if unnecessary"
        else:
            return f"Access Analyzer finding: {finding_type}"

    def update_terraform_policies(self, recommendations: Dict[str, Dict]) -> bool:
        """Update Terraform files with policy recommendations and create PR
        
        Args:
            recommendations: Dictionary of policy recommendations by resource
            
        Returns:
            True if updates were successful, False otherwise
        """
        try:
            logger.info(f"Processing {len(recommendations)} terraform policy updates")
            
            if not recommendations:
                logger.info("No recommendations to process")
                return True
            
            # Import GitHub PR handler
            from .github_pr import GitHubPRHandler
            
            # Initialize GitHub handler
            github_handler = GitHubPRHandler(
                github_token=self.github_token,
                repo_name=self.repo_name
            )
            
            # Group recommendations by type for better organization
            policy_files = {}
            terraform_files = {}
            summary_stats = {
                'total_recommendations': len(recommendations),
                'by_type': {},
                'by_confidence': {},
                'by_action_required': {}
            }
            
            logger.info("Analyzing recommendations and generating Terraform files...")
            
            for resource_key, recommendation in recommendations.items():
                self._log_recommendation_summary(resource_key, recommendation, summary_stats)
                
                # Generate Terraform content based on recommendation type
                terraform_content = self._generate_terraform_content(resource_key, recommendation)
                if terraform_content:
                    file_path = self._get_terraform_file_path(resource_key, recommendation)
                    terraform_files[file_path] = terraform_content
                    
                # Generate policy JSON files for policies with actual content
                policy_content = self._generate_policy_json(recommendation)
                if policy_content:
                    policy_file_path = self._get_policy_file_path(resource_key, recommendation)
                    policy_files[policy_file_path] = policy_content
            
            if not terraform_files and not policy_files:
                logger.warning("No Terraform or policy files generated from recommendations")
                return False
            
            # Combine all files for the PR
            all_files = {**terraform_files, **policy_files}
            
            # Generate comprehensive PR content
            pr_title, pr_body = self._generate_pr_content(recommendations, summary_stats)
            
            logger.info(f"Creating PR with {len(all_files)} files: {list(all_files.keys())}")
            
            # Create the pull request
            pr_result = github_handler.create_pull_request(
                title=pr_title,
                body=pr_body,
                base_branch="main",
                head_branch=f"iam-policy-updates-{self._get_timestamp()}",
                policy_changes=all_files
            )
            
            if pr_result.get("status") == "success":
                logger.info(f"Successfully created PR: {pr_result.get('pr_url')}")
                logger.info(f"PR #{pr_result.get('pr_number')}: {pr_title}")
                return True
            else:
                logger.error(f"Failed to create PR: {pr_result.get('error')}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating terraform policies: {str(e)}")
            return False
    
    def _log_recommendation_summary(self, resource_key: str, recommendation: Dict, summary_stats: Dict) -> None:
        """Log and track recommendation statistics"""
        rec_type = recommendation.get('recommendation_type', 'unknown')
        confidence = recommendation.get('confidence', 'unknown')
        action_required = recommendation.get('action_required', 'unknown')
        
        # Update summary statistics
        summary_stats['by_type'][rec_type] = summary_stats['by_type'].get(rec_type, 0) + 1
        summary_stats['by_confidence'][confidence] = summary_stats['by_confidence'].get(confidence, 0) + 1
        summary_stats['by_action_required'][action_required] = summary_stats['by_action_required'].get(action_required, 0) + 1
        
        logger.info(f"Recommendation for {resource_key}:")
        logger.info(f"  - Type: {rec_type}")
        logger.info(f"  - Confidence: {confidence}")
        logger.info(f"  - Action Required: {action_required}")
        logger.info(f"  - Finding Type: {recommendation.get('finding_type', 'unknown')}")
        logger.info(f"  - Reason: {recommendation.get('recommendation_reason', 'No reason provided')}")
        
        if recommendation.get('unused_actions'):
            logger.info(f"  - Unused actions ({len(recommendation['unused_actions'])}): {recommendation['unused_actions'][:3]}...")
    
    def _generate_terraform_content(self, resource_key: str, recommendation: Dict) -> Optional[str]:
        """Generate Terraform HCL content based on recommendation"""
        try:
            rec_type = recommendation.get('recommendation_type', 'unknown')
            resource_name = recommendation.get('resource_name', 'unknown')
            resource_type = recommendation.get('resource_type', 'unknown')
            tf_resource_name = recommendation.get('tf_resource_name', resource_name.replace('-', '_'))
            
            # Generate different Terraform content based on recommendation type
            if rec_type == 'policy_optimization' and recommendation.get('recommended_policy'):
                return self._generate_policy_terraform(tf_resource_name, recommendation['recommended_policy'])
            
            elif rec_type == 'least_privilege_suggestion' and recommendation.get('recommended_policy'):
                return self._generate_policy_terraform(tf_resource_name, recommendation['recommended_policy'])
            
            elif rec_type == 'remove_unused_permissions':
                return self._generate_comment_terraform(resource_key, recommendation)
            
            elif rec_type in ['security_review', 'credential_review', 'removal_candidate']:
                return self._generate_comment_terraform(resource_key, recommendation)
            
            else:
                return self._generate_comment_terraform(resource_key, recommendation)
                
        except Exception as e:
            logger.error(f"Error generating Terraform content for {resource_key}: {str(e)}")
            return None
    
    def _generate_policy_terraform(self, tf_resource_name: str, policy: Dict) -> str:
        """Generate Terraform HCL for an IAM policy"""
        policy_json = json.dumps(policy, indent=2)
        
        return f'''# Generated IAM policy based on Access Analyzer recommendations
resource "aws_iam_policy" "least_privilege_{tf_resource_name}" {{
  name        = "least-privilege-{tf_resource_name}"
  description = "Least privilege policy generated from Access Analyzer findings"
  
  policy = jsonencode({policy_json})
  
  tags = {{
    Source      = "AccessAnalyzer"
    GeneratedBy = "LeastPrivilegeOptimizer"
    Purpose     = "LeastPrivilege"
  }}
}}

# Attach the policy to the corresponding resource
# Note: Review and uncomment the appropriate attachment below

# For IAM User:
# resource "aws_iam_user_policy_attachment" "{tf_resource_name}_least_privilege" {{
#   user       = aws_iam_user.{tf_resource_name}.name
#   policy_arn = aws_iam_policy.least_privilege_{tf_resource_name}.arn
# }}

# For IAM Role:
# resource "aws_iam_role_policy_attachment" "{tf_resource_name}_least_privilege" {{
#   role       = aws_iam_role.{tf_resource_name}.name
#   policy_arn = aws_iam_policy.least_privilege_{tf_resource_name}.arn
# }}

# For IAM Group:
# resource "aws_iam_group_policy_attachment" "{tf_resource_name}_least_privilege" {{
#   group      = aws_iam_group.{tf_resource_name}.name
#   policy_arn = aws_iam_policy.least_privilege_{tf_resource_name}.arn
# }}
'''
    
    def _generate_comment_terraform(self, resource_key: str, recommendation: Dict) -> str:
        """Generate Terraform comment block with manual review instructions"""
        finding_id = recommendation.get('finding_id', 'unknown')
        finding_type = recommendation.get('finding_type', 'unknown')
        rec_type = recommendation.get('recommendation_type', 'unknown')
        reason = recommendation.get('recommendation_reason', 'Manual review required')
        action_required = recommendation.get('action_required', 'review')
        
        content = f'''# Access Analyzer Finding: {finding_id}
# Resource: {resource_key}
# Finding Type: {finding_type}
# Recommendation Type: {rec_type}
#
# MANUAL REVIEW REQUIRED
# {reason}
#
# Action Required: {action_required}
'''
        
        if recommendation.get('unused_actions'):
            unused_actions = recommendation['unused_actions']
            content += f'''#
# Unused Actions Detected ({len(unused_actions)}):
'''
            for action in unused_actions[:10]:  # Show first 10 actions
                content += f'#   - {action}\n'
            if len(unused_actions) > 10:
                content += f'#   ... and {len(unused_actions) - 10} more\n'
        
        if recommendation.get('finding_details'):
            content += f'''#
# Additional Finding Details:
# {json.dumps(recommendation['finding_details'], indent=2).replace(chr(10), chr(10) + '# ')}
'''
        
        content += '''#
# Next Steps:
# 1. Review the finding details above
# 2. Implement appropriate security measures
# 3. Update or remove this comment when resolved
# 4. Consider creating specific Terraform resources if needed

'''
        return content
    
    def _generate_policy_json(self, recommendation: Dict) -> Optional[Dict]:
        """Generate policy JSON content if available"""
        recommended_policy = recommendation.get('recommended_policy')
        if recommended_policy and isinstance(recommended_policy, dict) and recommended_policy.get('Statement'):
            return recommended_policy
        return None
    
    def _get_terraform_file_path(self, resource_key: str, recommendation: Dict) -> str:
        """Generate appropriate file path for Terraform content"""
        tf_resource_name = recommendation.get('tf_resource_name', resource_key.replace('-', '_').replace('.', '_'))
        rec_type = recommendation.get('recommendation_type', 'review')
        
        if rec_type in ['policy_optimization', 'least_privilege_suggestion']:
            return f"terraform/policies/least_privilege_{tf_resource_name}.tf"
        else:
            return f"terraform/reviews/review_{tf_resource_name}.tf"
    
    def _get_policy_file_path(self, resource_key: str, recommendation: Dict) -> str:
        """Generate appropriate file path for policy JSON"""
        tf_resource_name = recommendation.get('tf_resource_name', resource_key.replace('-', '_').replace('.', '_'))
        return f"policies/generated/least_privilege_{tf_resource_name}.json"
    
    def _generate_pr_content(self, recommendations: Dict, summary_stats: Dict) -> tuple[str, str]:
        """Generate PR title and body"""
        total = summary_stats['total_recommendations']
        
        # Generate title
        title = f"IAM Policy Updates - {total} Access Analyzer Recommendations"
        
        # Generate comprehensive body
        body = f"""# IAM Policy Updates - Least Privilege Optimization

This PR contains automated updates based on AWS IAM Access Analyzer findings.

## 📊 Summary

- **Total Recommendations**: {total}
- **Generated Files**: {len([k for k in recommendations.keys()])}
- **Analysis Date**: {self._get_timestamp()}

### Recommendation Types
"""
        
        for rec_type, count in summary_stats['by_type'].items():
            body += f"- **{rec_type.replace('_', ' ').title()}**: {count}\n"
        
        body += "\n### Confidence Levels\n"
        for confidence, count in summary_stats['by_confidence'].items():
            body += f"- **{confidence.title()}**: {count}\n"
        
        body += "\n### Actions Required\n"
        for action, count in summary_stats['by_action_required'].items():
            body += f"- **{action.replace('_', ' ').title()}**: {count}\n"
        
        body += f"""

## 🔍 Changes Included

### Policy Optimizations
Files with automated policy suggestions based on actual usage patterns.

### Security Reviews  
Files requiring manual review for security findings.

### Unused Permission Removal
Recommendations for removing unused IAM permissions.

## 🚀 Implementation Guide

### 1. Review Generated Policies
- Check `terraform/policies/` for least privilege policy suggestions
- Verify the policies match your security requirements
- Test policies in a non-production environment first

### 2. Manual Reviews Required
- Check `terraform/reviews/` for items requiring manual attention
- Address security findings and external access issues
- Remove or update resources as recommended

### 3. Apply Changes
```bash
cd terraform
terraform plan
terraform apply
```

## 🔒 Security Considerations

- All policy changes are based on AWS IAM Access Analyzer findings
- High confidence recommendations are generally safe to implement
- Medium/Low confidence items require manual review
- Test changes in development environment first

## 📋 Checklist

- [ ] Review all generated policy files
- [ ] Address manual review items
- [ ] Test changes in development
- [ ] Update any application configurations if needed
- [ ] Apply Terraform changes
- [ ] Monitor for any access issues post-deployment

---

*This PR was generated automatically by the Least Privilege Optimizer based on Access Analyzer findings.*
*Generated at: {self._get_timestamp()}*
"""
        
        return title, body
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for file naming and logging"""
        from datetime import datetime
        return datetime.now().strftime("%Y%m%d-%H%M%S")