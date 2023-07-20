from celery import Task
from redis.exceptions import ResponseError


class RedisTaskWithRetry(Task):
    autoretry_for = (ResponseError,)
    retry_kwargs = {'max_retries': 3}
    retry_backoff = True
    default_retry_delay = 10
