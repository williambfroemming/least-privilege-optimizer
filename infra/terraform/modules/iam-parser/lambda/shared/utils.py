# shared/utils.py - Common utilities for all Lambda functions

import json
import logging
import os
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

class IAMAnalyzerError(Exception):
    """Custom exception for IAM Analyzer errors"""
    pass

def setup_logging():
    """Configure logging for Lambda functions"""
    log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
    logger.setLevel(getattr(logging, log_level, logging.INFO))
    
    # Remove default handler and add our own
    if logger.handlers:
        for handler in logger.handlers:
            logger.removeHandler(handler)
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '[%(levelname)s] %(asctime)s - %(name)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

def create_error_response(status_code: int, error_message: str, preserve_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Create a standardized error response that preserves data flow"""
    response = {
        'statusCode': status_code,
        'error': error_message,
        'success': False
    }
    
    # Preserve data from previous steps for workflow continuity
    if preserve_data:
        response.update(preserve_data)
    
    return response

def create_success_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a standardized success response"""
    response = {
        'statusCode': 200,
        'success': True
    }
    response.update(data)
    return response

def validate_environment_variables(required_vars: List[str]) -> Dict[str, str]:
    """Validate that required environment variables are set"""
    env_vars = {}
    missing_vars = []
    
    for var in required_vars:
        value = os.environ.get(var)
        if not value:
            missing_vars.append(var)
        else:
            env_vars[var] = value
    
    if missing_vars:
        raise IAMAnalyzerError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    return env_vars

def safe_json_loads(json_string: str, default: Any = None) -> Any:
    """Safely parse JSON string with fallback"""
    try:
        return json.loads(json_string)
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning(f"Failed to parse JSON: {e}")
        return default

def handle_aws_error(func):
    """Decorator to handle AWS service errors consistently"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"AWS API error in {func.__name__}: {error_code} - {error_message}")
            raise IAMAnalyzerError(f"AWS API error: {error_message}")
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {e}")
            raise IAMAnalyzerError(f"Unexpected error: {str(e)}")
    return wrapper

def extract_step_input(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extract actual input from Step Function event structure"""
    # Handle Step Function payload wrapper
    if 'Payload' in event:
        return event['Payload']
    return event

def log_function_start(function_name: str, event_keys: List[str]):
    """Log function start with input summary"""
    logger.info(f"🚀 Starting {function_name}")
    logger.info(f"📥 Input keys: {event_keys}")

def log_function_end(function_name: str, success: bool, output_keys: List[str] = None):
    """Log function completion"""
    status = "✅ SUCCESS" if success else "❌ FAILED"
    logger.info(f"🏁 {function_name} completed: {status}")
    if output_keys:
        logger.info(f"📤 Output keys: {output_keys}")

def clean_arn_list(arns: List[str]) -> List[str]:
    """Clean ARN list by removing template variables"""
    clean_arns = []
    for arn in arns:
        if '${' not in arn and arn.startswith('arn:aws:iam:'):
            clean_arns.append(arn)
        else:
            logger.warning(f"Skipping templated ARN: {arn}")
    return clean_arns

def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

# Constants
DEFAULT_CLOUDTRAIL_RETENTION_DAYS = 30
MAX_CLOUDTRAIL_QUERY_WAIT_MINUTES = 15
GITHUB_API_BASE_URL = "https://api.github.com"