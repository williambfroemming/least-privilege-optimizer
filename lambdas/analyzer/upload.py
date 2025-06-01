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
    
    # Create and upload layer
    logger.info("Creating Lambda layer")
    layer_zip = create_layer_package()
    
    # Initialize Lambda client with explicit region
    lambda_client = boto3.client('lambda', region_name='us-east-1')  # or your preferred region
    
    # Create or update layer
    try:
        layer_response = lambda_client.publish_layer_version(
            LayerName='iam-analyzer-deps',
            Description='Dependencies for IAM Analyzer',
            Content={'ZipFile': layer_zip},
            CompatibleRuntimes=['python3.9'],
            CompatibleArchitectures=['x86_64']
        )
        layer_arn = layer_response['LayerVersionArn']
        logger.info(f"Successfully created layer: {layer_arn}")
    except Exception as e:
        logger.error(f"Error creating layer: {str(e)}")
        raise

    # Create function package
    logger.info("Creating function package")
    zip_content = create_function_package()
    
    # Update Lambda function
    try:
        logger.info("Updating Lambda function code and configuration")
        lambda_client.update_function_configuration(
            FunctionName='iam-analyzer-engine',
            Layers=[layer_arn]
        )
        time.sleep(20)  # Wait for the layer to be ready
        logger.info("Updating Lambda function code")
        response = lambda_client.update_function_code(
            FunctionName='iam-analyzer-engine',
            ZipFile=zip_content
        )
        logger.info(f"Successfully updated Lambda function: {response['FunctionName']}")
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
        deploy_lambda()
    except Exception as e:
        logger.critical(f"Deployment failed: {str(e)}")
        exit(1)