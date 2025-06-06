import json
import os
import boto3

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    bucket = os.environ['S3_BUCKET']
    key = os.environ['S3_KEY']

    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        contents = json.loads(response['Body'].read())
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Read IAM data from S3',
                'resource_counts': {k: len(v) for k, v in contents.items()}
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }