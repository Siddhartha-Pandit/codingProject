import os
import logging
from twilio.rest import Client
from django.conf import settings

logger = logging.getLogger(__name__)

def send_msg(to, text):
    account_sid = settings.TWILIO_ACCOUNT_SID
    auth_token = settings.TWILIO_AUTH_TOKEN
    from_number = settings.TWILIO_PHONE_NUMBER

    if not account_sid or not auth_token or not from_number:
        logger.error("Twilio configuration is incomplete in settings.")
        raise Exception("Twilio configuration is incomplete.")

    try:
        client = Client(account_sid, auth_token)
        logger.info(f"Twilio client created for account SID: {account_sid}")
        message = client.messages.create(
            body=text,
            from_=from_number,
            to=to,
        )
        logger.info(f"SMS sent to {to} with message SID: {message.sid}")
        return message
    except Exception as e:
        logger.error(f"Error sending SMS to {to}: {str(e)}")
        raise
