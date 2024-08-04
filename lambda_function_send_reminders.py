import json
import logging
import os
import boto3
from twilio.rest import Client
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize the DynamoDB resource
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Tasks')

def send_reminder_sms(phone_number, task_title, due_date):
    ACCOUNT_SID = os.environ['TWILIO_ACCOUNT_SID']
    AUTH_TOKEN = os.environ['TWILIO_AUTH_TOKEN']
    TWILIO_PHONE_NUMBER = os.environ['TWILIO_PHONE_NUMBER']

    client = Client(ACCOUNT_SID, AUTH_TOKEN)

    MESSAGE = f"Reminder: Your task '{task_title}' is due on {due_date}."

    try:
        message = client.messages.create(
            body=MESSAGE,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        logger.info(f"SMS sent! Message SID: {message.sid}")
    except Exception as e:
        logger.error(f"Error sending SMS: {e}")

def lambda_handler(event, context):
    today_date = datetime.utcnow().strftime('%Y-%m-%d')

    try:
        response = table.query(
            IndexName='UserDueDateIndex',
            KeyConditionExpression='due_date = :due_date',
            ExpressionAttributeValues={':due_date': today_date}
        )

        tasks = response.get('Items', [])
        for task in tasks:
            phone_number = task.get('phone_number')
            task_title = task.get('title', "No Title")
            due_date = task.get('due_date', "No Due Date")
            send_reminder_sms(phone_number, task_title, due_date)

        return {
            'statusCode': 200,
            'body': 'SMS reminders sent successfully'
        }
    except Exception as e:
        logger.error(f"Error processing tasks: {e}")
        return {
            'statusCode': 500,
            'body': f'Error processing tasks: {e}'
        }
