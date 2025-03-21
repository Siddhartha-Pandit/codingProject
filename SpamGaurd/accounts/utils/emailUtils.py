import logging
from django.core.mail import send_mail
from django.conf import settings

logger = logging.getLogger(__name__)

def send_verification_email(to, subject, message):
 
    try:
        from_email = settings.DEFAULT_FROM_EMAIL
        send_mail(subject, message, from_email, [to], fail_silently=False)
        logger.info(f"Email sent successfully to {to}.")
        return True
    except Exception as e:
        logger.error(f"Error sending email to {to}: {str(e)}")
        raise
