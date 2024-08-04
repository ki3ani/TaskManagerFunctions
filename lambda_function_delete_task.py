import json
import boto3
import logging
import jwt
from jwt import InvalidTokenError

# Initialize the logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize the DynamoDB resource
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Tasks')

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")

    try:
        # Check if the Authorization header is present
        if 'headers' not in event or 'Authorization' not in event['headers']:
            raise KeyError("Authorization header is missing")

        # Extract JWT token from the Authorization header
        auth_header = event['headers']['Authorization']
        logger.info(f"Authorization header: {auth_header}")

        auth_parts = auth_header.split()
        if len(auth_parts) != 2 or auth_parts[0].lower() != 'bearer':
            raise KeyError("Invalid Authorization header format")
        token = auth_parts[1]

        decoded_token = jwt.decode(token, options={"verify_signature": False})
        logger.info(f"Decoded token: {decoded_token}")

        if 'sub' not in decoded_token:
            raise KeyError("User ID (sub) not found in the token")
        user_id = decoded_token['sub']

        logger.info(f"Delete task request received for user: {user_id}")

        # Get task_id from path parameters
        if 'pathParameters' not in event or 'taskId' not in event['pathParameters']:
            raise ValueError("task_id is missing in path parameters")
        task_id = event['pathParameters']['taskId']

        # Delete the item from DynamoDB
        table.delete_item(
            Key={
                'user_id': user_id,
                'task_id': task_id
            }
        )

        logger.info(f"Task deleted successfully: {task_id}")
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Task deleted successfully'})
        }
    except KeyError as e:
        logger.error(f"Unauthorized - {str(e)}")
        return {
            'statusCode': 401,
            'body': json.dumps({'error': f'Unauthorized - {str(e)}'})
        }
    except InvalidTokenError as e:
        logger.error(f"Unauthorized - Invalid token: {str(e)}")
        return {
            'statusCode': 401,
            'body': json.dumps({'error': 'Unauthorized - Invalid token'})
        }
    except ValueError as e:
        logger.error(f"Bad Request - {str(e)}")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': f'Bad Request - {str(e)}'})
        }
    except Exception as e:
        logger.error(f"Error deleting task: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
