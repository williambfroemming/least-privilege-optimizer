# shared/__init__.py
"""
Shared utilities for IAM Analyzer Lambda functions
"""

from .utils import (
    setup_logging,
    log_function_start,
    log_function_end,
    create_error_response,
    create_success_response,
    validate_environment_variables,
    handle_aws_error,
    extract_step_input,
    IAMAnalyzerError,
    clean_arn_list,
    format_file_size,
    safe_json_loads
)

from .aws_clients import (
    get_s3_client,
    get_cloudtrail_client,
    get_ssm_client
)

__all__ = [
    'setup_logging',
    'log_function_start', 
    'log_function_end',
    'create_error_response',
    'create_success_response',
    'validate_environment_variables',
    'handle_aws_error',
    'extract_step_input',
    'IAMAnalyzerError',
    'clean_arn_list',
    'format_file_size',
    'safe_json_loads',
    'get_s3_client',
    'get_cloudtrail_client',
    'get_ssm_client'
]