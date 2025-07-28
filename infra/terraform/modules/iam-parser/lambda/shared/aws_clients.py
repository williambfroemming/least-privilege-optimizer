# shared/aws_clients.py - AWS client initialization

import boto3
import logging
from typing import Optional
from botocore.config import Config

logger = logging.getLogger(__name__)

# Client configuration for better performance
CLIENT_CONFIG = Config(
    region_name=None,  # Use default region
    retries={
        'max_attempts': 3,
        'mode': 'adaptive'
    },
    max_pool_connections=10
)

# Cache clients to reuse across invocations
_s3_client = None
_cloudtrail_client = None
_ssm_client = None

def get_s3_client():
    """Get cached S3 client"""
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client('s3', config=CLIENT_CONFIG)
        logger.debug("Initialized S3 client")
    return _s3_client

def get_cloudtrail_client():
    """Get cached CloudTrail client"""
    global _cloudtrail_client
    if _cloudtrail_client is None:
        _cloudtrail_client = boto3.client('cloudtrail', config=CLIENT_CONFIG)
        logger.debug("Initialized CloudTrail client")
    return _cloudtrail_client

def get_ssm_client():
    """Get cached SSM client"""
    global _ssm_client
    if _ssm_client is None:
        _ssm_client = boto3.client('ssm', config=CLIENT_CONFIG)
        logger.debug("Initialized SSM client")
    return _ssm_client