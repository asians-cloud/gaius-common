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

# Sentinel so callers can distinguish "no default given" from "default is None/{}".
_NO_DEFAULT = object()


class PlanClientError(Exception):
    """Raised when a call to the Plan internal API fails (transport or HTTP error)."""


def _base_url():
    url = getattr(settings, "PLAN_INTERNAL_URL", None)
    if not url:
        raise PlanClientError("PLAN_INTERNAL_URL is not configured")
    return url if url.endswith("/") else url + "/"


def _get(path, params=None, not_found_default=_NO_DEFAULT):
    """GET a Plan internal endpoint.

    A 404 means "no such object" (Plan uses DRF's get_object_or_404). When
    ``not_found_default`` is supplied it is returned in that case instead of
    raising, so callers whose contract is "value or empty" don't have to treat a
    legitimately-absent record as a hard error. Any other transport/HTTP error
    still raises :class:`PlanClientError`.
    """
    url = urljoin(_base_url(), path)
    token = getattr(settings, "PLAN_SERVICE_TOKEN", "")
    timeout = getattr(settings, "PLAN_HTTP_TIMEOUT", DEFAULT_TIMEOUT)
    try:
        resp = requests.get(
            url,
            params=params or {},
            headers={
                "Authorization": f"Token {token}",
                # In-cluster calls are plain HTTP, but Plan runs
                # SECURE_SSL_REDIRECT=True. Assert the request is already
                # "secure" (Plan trusts X-Forwarded-Proto via
                # SECURE_PROXY_SSL_HEADER) so it isn't 301-redirected to https.
                "X-Forwarded-Proto": "https",
            },
            timeout=timeout,
        )
        if resp.status_code == 404 and not_found_default is not _NO_DEFAULT:
            return not_found_default
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        logger.error("Plan API call failed: GET %s params=%s err=%s", url, params, e)
        raise PlanClientError(str(e)) from e


def get_subscription(cname):
    """Replaces `plan.get_subscription`. Returns the subscription dict, or {} if none.

    A cname with no subscription is a normal "not found", not an error: Plan
    answers 404, which we map to ``{}`` so callers' ``if not subscription``
    guards work (matching the old Celery RPC's falsy return).
    """
    return _get(
        "plan/internal/subscription-by-cname/", {"cname": cname}, not_found_default={}
    )


def get_quota_by_cname(cname):
    """Replaces `plan.get_quota_by_cname`. Returns the quota dict."""
    return _get("plan/internal/quota-by-cname/", {"cname": cname})


def subscriptions_by_host(host=None):
    """Replaces `plan.subscriptions_by_host`. Returns a list of subscription dicts."""
    return _get(
        "plan/internal/subscriptions-by-host/", {"host": host} if host else None
    )


def find_all_cnames():
    """Replaces `plan.find_all_cnames`. Returns a list of "cname.czone" strings."""
    return _get("plan/internal/cnames/")
