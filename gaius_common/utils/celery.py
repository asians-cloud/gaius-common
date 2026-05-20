from celery import Task
from redis.exceptions import ConnectionError as RedisConnectionError, TimeoutError as RedisTimeoutError


# Retry on transient Redis failures (network drops, broker timeouts).
# `ResponseError` was previously listed but it's a command-level error
# (wrong type / syntax) that retrying does not fix.
class RedisTaskWithRetry(Task):
    autoretry_for = (RedisConnectionError, RedisTimeoutError)
    retry_kwargs = {'max_retries': 3}
    retry_backoff = True
    default_retry_delay = 10
