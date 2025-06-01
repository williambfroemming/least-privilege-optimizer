
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger(service="test-lambda")

@logger.inject_lambda_context
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    """
    Basic Lambda function with powertools logging
    """
    logger.info("Lambda function invoked", extra={"event": event})
    
    try:
        response = {
            "statusCode": 200,
            "body": "Hello from Lambda!"
        }
        logger.info("Lambda execution successful", extra={"response": response})
        return response
        
    except Exception as e:
        logger.exception("Lambda execution failed")
        raise e
