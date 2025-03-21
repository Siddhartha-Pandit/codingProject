import redis
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

redis_pool = redis.ConnectionPool(
    host=settings.REDIS_HOST,     
    port=settings.REDIS_PORT,     
    db=settings.REDIS_DB,         
    decode_responses=True         
)
redis_client = redis.StrictRedis(connection_pool=redis_pool)

def get_redis_client():
    ##return the redis client
    return redis_client