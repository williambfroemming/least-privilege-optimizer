import os
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

def create_requirements_package():
    # Create a temporary directory for packages
    if os.path.exists('package'):
        shutil.rmtree('package')
    os.makedirs('package')
    logger.info("Created temporary package directory")

    # Install requirements to the package directory
    if os.path.exists('requirements.txt'):
        logger.info("Installing requirements from requirements.txt")
        subprocess.check_call([
            'pip', 'install',
            '-r', 'requirements.txt',
            '--target', './package'
        ])
        logger.info("Successfully installed requirements")

def zip_and_upload_to_lambda():
    logger.info("Starting Lambda deployment process")
    # Create a BytesIO object to store the zip file
    zip_buffer = BytesIO()
    
    # Install dependencies to package directory
    create_requirements_package()
    
    # Create zip file in memory
    logger.info("Creating deployment package")
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # First add all the packages
        if os.path.exists('package'):
            for root, dirs, files in os.walk('package'):
                for file in files:
                    file_path = os.path.join(root, file)
                    arc_name = os.path.relpath(file_path, 'package')
                    zip_file.write(file_path, arc_name)
                    
        # Then add all application files
        for root, dirs, files in os.walk('.'):
            for file in files:
                # Skip .git folder, __pycache__, and package directory
                if '.git' in root or '__pycache__' in root or 'package' in root:
                    continue
                file_path = os.path.join(root, file)
                # Add file to zip with relative path
                arc_name = os.path.relpath(file_path, '.')
                zip_file.write(file_path, arc_name)
    
    logger.info("Deployment package created successfully")

    # Get the zip file content
    zip_buffer.seek(0)
    zip_content = zip_buffer.read()

    # Initialize Lambda client with specified region
    lambda_client = boto3.client('lambda', region_name='us-east-1')

    try:
        # Update Lambda function code
        logger.info("Uploading to Lambda function 'iam-analyzer-engine'")
        response = lambda_client.update_function_code(
            FunctionName='iam-analyzer-engine',
            ZipFile=zip_content
        )
        logger.info(f"Successfully uploaded to Lambda function: {response['FunctionName']}")
        
        # Cleanup
        if os.path.exists('package'):
            shutil.rmtree('package')
            logger.info("Cleaned up temporary files")
            
        return response
    except Exception as e:
        logger.error(f"Error uploading to Lambda: {str(e)}")
        raise e

if __name__ == "__main__":
    try:
        zip_and_upload_to_lambda()
    except Exception as e:
        logger.critical(f"Deployment failed: {str(e)}")
        exit(1)