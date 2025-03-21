import secrets
import hashlib
import logging
from django.conf import settings
from .redisClient import get_redis_client
from .twillioClient import send_msg
logger = logging.getLogger(__name__)
redis_client = get_redis_client()

RATE_LIMIT_THRESHOLD = 5
RATE_LIMIT_WINDOW = 60

def generate_otp(length=6):
    digits = "0123456789"
    otp = ''.join(secrets.choice(digits) for _ in range(length))
    return otp

def hash_otp(otp):
    return hashlib.sha256(otp.encode('utf-8')).hexdigest()

def store_otp(phone, otp, ttl=300):
    key = f"otp:{phone}"
    otp_hash = hash_otp(otp)
    try:
        redis_client.setex(key, ttl, otp_hash)
        logger.info(f"The hashed generated for stored phone: {phone} with TTL {ttl} seconds.")
    except Exception as e:
        logger.error(f"Error while storing OTP for {phone}: {str(e)}")
        raise

def get_stored_otp_hash(phone):
    key = f"otp:{phone}"
    try:
        return redis_client.get(key)
    except Exception as e:
        logger.error(f"Error while retrieving OTP for {phone}: {str(e)}")
        return None

def verify_otp(phone, otp):
    key = f"otp:{phone}"
    try:
        stored_hash = redis_client.get(key)
    except Exception as e:
        logger.error(f"Error while verifying OTP for {phone}: {str(e)}")
        return False, "Internal error while OTP verification."

    if not stored_hash:
        logger.warning(f"OTP may be expired or not found for phone {phone}.")
        return False, "OTP may be expired or not found."
    
    provided_hash = hash_otp(otp)
    if provided_hash == stored_hash:
        try:
            redis_client.delete(key)
        except Exception as e:
            logger.error(f"Error while deleting OTP for {phone}: {str(e)}")
        logger.info(f"OTP is verified successfully for phone {phone}.")
        return True, "OTP is verified successfully."
    
    logger.warning(f"The OTP is invalid  for phone {phone}.")
    return False, "Invalid OTP."

def is_rate_limited(phone):
    key = f"otp_requests:{phone}"
    try:
        count = redis_client.get(key)
        if count and int(count) >= RATE_LIMIT_THRESHOLD:
            logger.warning(f"Rate limit is exceeded for phone {phone}.")
            return True
    except Exception as e:
        logger.error(f"Error while rate limit check for {phone}: {str(e)}")
    return False

def increment_rate_limit(phone):
    key = f"otp_requests:{phone}"
    try:
        count = redis_client.get(key)
        if count and int(count) >= RATE_LIMIT_THRESHOLD:
            logger.warning(f"Rate limit is exceeded for phone {phone}.")
            return True
    except Exception as e:
        logger.error(f"Error while rate limit check for {phone}: {str(e)}")
    return False

def increment_rate_limit(phone):
    key = f"otp_requests:{phone}"
    try:
        current = redis_client.incr(key)
        if current == 1:
            # Set expiration when first incremented.
            redis_client.expire(key, RATE_LIMIT_WINDOW)
        logger.info(f"OTP request count for {phone}: {current}.")
        return current
    except Exception as e:
        logger.error(f"Error incrementing for rate limit for {phone}: {str(e)}")
        return None

def reset_rate_limit(phone):
    key = f"otp_requests:{phone}"
    try:
        redis_client.delete(key)
        logger.info(f"OTP rate limit for reset  phone {phone}.")
    except Exception as e:
        logger.error(f"Error while resetting rate limit for {phone}: {str(e)}")

def send_sms(phone, otp):
    try:
        send_msg(phone, f"Your OTP is {otp}")
        logger.info(f"SMS is sent to {phone}: Your OTP is {otp}")

    except Exception as e:
        logger.info(f"Error Sending SMS to {phone}")
        raise

        
def send_otp(phone):
    if is_rate_limited(phone):
        return False, "Rate is  limit exceeded. Please try again later."
    
    otp = generate_otp(length=6)
    try:
        store_otp(phone, otp, ttl=300) 
        increment_rate_limit(phone)
        send_sms(phone, otp)
        return True, "OTP sent successfully."
    except Exception as e:
        logger.error(f"Error sending OTP for {phone}: {str(e)}")
        return False, "Failed to send OTP due to an internal error."