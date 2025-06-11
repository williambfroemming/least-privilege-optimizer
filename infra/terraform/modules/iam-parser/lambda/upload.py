import os
import time
import boto3
import zipfile
from io import BytesIO
import subprocess
import shutil
import logging
import colorlog

# Configure logger
def setup_logger():
    """Configure colorized logging"""
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    ))
    
    logger = colorlog.getLogger('deploy')
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

logger = setup_logger()

def get_config():
    """Get configuration from environment variables with defaults"""
    config = {
        'function_name': os.environ.get('LAMBDA_FUNCTION_NAME', 'iam-analyzer-engine'),
        'layer_name': os.environ.get('LAMBDA_LAYER_NAME', 'iam-analyzer-deps'),
        'region': os.environ.get('AWS_DEFAULT_REGION', os.environ.get('AWS_REGION', 'us-east-1')),
        'runtime': os.environ.get('LAMBDA_RUNTIME', 'python3.9'),
        'architecture': os.environ.get('LAMBDA_ARCHITECTURE', 'x86_64')
    }
    
    logger.info(f"Configuration: {config}")
    return config

def create_layer_package():
    """Create a Lambda layer package with all dependencies"""
    if os.path.exists('layer'):
        shutil.rmtree('layer')
    os.makedirs('layer/python')
    logger.info("Created temporary layer directory")

    # Install layer requirements
    if os.path.exists('requirements.txt'):
        logger.info("Installing layer requirements")
        try:
            # First try with binary packages for speed
            subprocess.check_call([
                'pip', 'install',
                '-r', 'requirements.txt',
                '--target', './layer/python',
                '--platform', 'manylinux2014_x86_64',
                '--implementation', 'cp',
                '--python-version', '39',
                '--only-binary=:all:',
                '--upgrade'
            ])
            logger.info("Successfully installed binary packages")
        except subprocess.CalledProcessError:
            logger.warning("Binary-only installation failed, trying with source packages allowed")
            # If binary-only fails, try again allowing source packages
            subprocess.check_call([
                'pip', 'install',
                '-r', 'requirements.txt',
                '--target', './layer/python',
                '--upgrade'
            ])
            logger.info("Successfully installed layer requirements")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install layer requirements: {str(e)}")
            raise

    # Create layer zip
    layer_zip = BytesIO()
    with zipfile.ZipFile(layer_zip, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, _, files in os.walk('layer'):
            for file in files:
                file_path = os.path.join(root, file)
                arc_name = os.path.relpath(file_path, 'layer')
                zip_file.write(file_path, arc_name)

    layer_zip.seek(0)
    return layer_zip.read()

def create_function_package():
    """Create a package with only the Lambda function code"""
    # Create zip file for Lambda function
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Add application files
        for root, _, files in os.walk('.'):
            for file in files:
                if (any(x in root for x in ['.git', '__pycache__', 'package', 'layer']) or
                    file in ['requirements.txt', 'upload.py']):
                    continue
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    arc_name = os.path.relpath(file_path, '.')
                    zip_file.write(file_path, arc_name)
    
    zip_buffer.seek(0)
    return zip_buffer.read()

def deploy_lambda():
    """Deploy the Lambda function and its layer"""
    logger.info("Starting Lambda deployment process")
    
    # Get configuration
    config = get_config()
    
    # Create and upload layer
    logger.info("Creating Lambda layer")
    layer_zip = create_layer_package()
    
    # Initialize Lambda client with configurable region
    lambda_client = boto3.client('lambda', region_name=config['region'])
    
    # Create or update layer
    try:
        layer_response = lambda_client.publish_layer_version(
            LayerName=config['layer_name'],
            Description='Dependencies for IAM Analyzer',
            Content={'ZipFile': layer_zip},
            CompatibleRuntimes=[config['runtime']],
            CompatibleArchitectures=[config['architecture']]
        )
        layer_arn = layer_response['LayerVersionArn']
        logger.info(f"Successfully created layer: {layer_arn}")
    except Exception as e:
        logger.error(f"Error creating layer: {str(e)}")
        raise

    # Create function package
    logger.info("Creating function package")
    zip_content = create_function_package()
    
    # Check if function exists
    function_exists = False
    try:
        lambda_client.get_function(FunctionName=config['function_name'])
        function_exists = True
        logger.info(f"Function {config['function_name']} exists, will update")
    except lambda_client.exceptions.ResourceNotFoundException:
        logger.info(f"Function {config['function_name']} does not exist, will create")
    except Exception as e:
        logger.error(f"Error checking function existence: {str(e)}")
        raise
    
    # Update or create Lambda function
    try:
        if function_exists:
            logger.info("Updating Lambda function configuration")
            lambda_client.update_function_configuration(
                FunctionName=config['function_name'],
                Layers=[layer_arn]
            )
            time.sleep(20)  # Wait for the layer to be ready
            
            logger.info("Updating Lambda function code")
            response = lambda_client.update_function_code(
                FunctionName=config['function_name'],
                ZipFile=zip_content
            )
            logger.info(f"Successfully updated Lambda function: {response['FunctionName']}")
        else:
            logger.warning("Function does not exist. This script only updates existing functions.")
            logger.warning("Please create the function first using Terraform or AWS CLI.")
            logger.info(f"Layer ARN for manual creation: {layer_arn}")
            return None
            
    except Exception as e:
        logger.error(f"Error updating Lambda: {str(e)}")
        raise
    finally:
        # Cleanup
        if os.path.exists('layer'):
            shutil.rmtree('layer')
        logger.info("Cleaned up temporary files")
    
    return response

if __name__ == "__main__":
    try:
        # Print configuration help
        logger.info("Environment variables you can set:")
        logger.info("  LAMBDA_FUNCTION_NAME - Lambda function name (default: iam-analyzer-engine)")
        logger.info("  LAMBDA_LAYER_NAME - Layer name (default: iam-analyzer-deps)")
        logger.info("  AWS_DEFAULT_REGION or AWS_REGION - AWS region (default: us-east-1)")
        logger.info("  LAMBDA_RUNTIME - Python runtime (default: python3.9)")
        logger.info("  LAMBDA_ARCHITECTURE - Architecture (default: x86_64)")
        logger.info("")
        
        result = deploy_lambda()
        if result:
            logger.info("Deployment completed successfully!")
        else:
            logger.warning("Deployment completed with warnings - check logs above")
    except Exception as e:
        logger.critical(f"Deployment failed: {str(e)}")
        exit(1)