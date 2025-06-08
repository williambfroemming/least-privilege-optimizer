from typing import Dict, List, Optional
import json
from aws_lambda_powertools import Logger
from github import Github, Auth
from botocore.exceptions import ClientError

logger = Logger(service="PolicyRecommender")

class PolicyRecommender:
    """Handles policy recommendations and terraform updates based on analyzer findings"""
    
    def __init__(self, github_token: str, repo_name: str):
        """Initialize PolicyRecommender
        
        Args:
            github_token: GitHub personal access token
            repo_name: Repository name in format 'owner/repo'
        """
        auth = Auth.Token(github_token)
        self.github = Github(auth=auth)
        self.repo = self.github.get_repo(repo_name)
        
    def process_findings(self, findings: List[Dict], resources: List[Dict]) -> Dict[str, Dict]:
        """Process analyzer findings and generate policy recommendations
        
        Args:
            findings: List of IAM Access Analyzer findings
            resources: List of resources from latest.json
            
        Returns:
            Dictionary mapping resource names to recommended policy changes
        """
        recommendations = {}
        
        # Create lookup for resources by ARN
        resource_lookup = {r['ResourceARN']: r for r in resources}
        
        for finding in findings:
            resource_arn = finding.get('resource', {}).get('arn')
            if not resource_arn or resource_arn not in resource_lookup:
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
            resource: Resource details from latest.json
            
        Returns:
            Dictionary with recommended policy changes
        """
        try:
            # Extract current and recommended permissions
            current_policy = finding.get('resource', {}).get('policy', {})
            analyzed_policy = finding.get('analyzedPolicy', {})
            
            if not current_policy or not analyzed_policy:
                return None
            
            return {
                'current_policy': current_policy,
                'recommended_policy': analyzed_policy,
                'resource_name': resource['ResourceName'],
                'resource_type': resource['ResourceType'],
                'finding_id': finding.get('id'),
                'tf_resource_name': resource.get('tf_resource_name')
            }
            
        except Exception as e:
            logger.error(f"Error generating recommendation: {str(e)}")
            return None
            
    def update_terraform_policies(self, recommendations: Dict[str, Dict]) -> bool:
        """Update Terraform files with policy recommendations
        
        Args:
            recommendations: Dictionary of policy recommendations by resource
            
        Returns:
            True if updates were successful, False otherwise
        """
        try:
            # TODO: Implement terraform file updates
            # This will:
            # 1. Clone/fetch terraform repo
            # 2. Find relevant policy files
            # 3. Update policies based on recommendations
            # 4. Create PR with changes
            
            logger.info("Terraform policy updates not yet implemented")
            return False
            
        except Exception as e:
            logger.error(f"Error updating terraform policies: {str(e)}")
            return False