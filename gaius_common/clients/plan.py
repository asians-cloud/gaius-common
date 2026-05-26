"""HTTP client for the Plan service's internal endpoints.

Replaces the synchronous `app.send_task('plan.*', ...).get()` Celery RPC with a
direct, bounded HTTP call to the Plan service. Reads configuration from Django
settings:

    PLAN_INTERNAL_URL    base URL of Plan's API, e.g. "http://gaius-plan/api/v2/"
    PLAN_SERVICE_TOKEN   DRF token of the service (admin) user used to authenticate
    PLAN_HTTP_TIMEOUT    optional, seconds (default 10)

Each function mirrors the response shape of the Celery task it replaces, so
callers can swap `send_task(...).get()` for these one-for-one.
"""
import logging
from urllib.parse import urljoin

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10


class PlanClientError(Exception):
    """Raised when a call to the Plan internal API fails (transport or HTTP error)."""


def _base_url():
    url = getattr(settings, "PLAN_INTERNAL_URL", None)
    if not url:
        raise PlanClientError("PLAN_INTERNAL_URL is not configured")
    return url if url.endswith("/") else url + "/"


def _get(path, params=None):
    url = urljoin(_base_url(), path)
    token = getattr(settings, "PLAN_SERVICE_TOKEN", "")
    timeout = getattr(settings, "PLAN_HTTP_TIMEOUT", DEFAULT_TIMEOUT)
    try:
        resp = requests.get(
            url,
            params=params or {},
            headers={"Authorization": f"Token {token}"},
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        logger.error("Plan API call failed: GET %s params=%s err=%s", url, params, e)
        raise PlanClientError(str(e)) from e


def get_subscription(cname):
    """Replaces `plan.get_subscription`. Returns the subscription dict, or {} if none."""
    return _get("plan/internal/subscription-by-cname/", {"cname": cname})


def get_quota_by_cname(cname):
    """Replaces `plan.get_quota_by_cname`. Returns the quota dict."""
    return _get("plan/internal/quota-by-cname/", {"cname": cname})


def subscriptions_by_host(host=None):
    """Replaces `plan.subscriptions_by_host`. Returns a list of subscription dicts."""
    return _get("plan/internal/subscriptions-by-host/", {"host": host} if host else None)


def find_all_cnames():
    """Replaces `plan.find_all_cnames`. Returns a list of "cname.czone" strings."""
    return _get("plan/internal/cnames/")
