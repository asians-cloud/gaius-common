"""HTTP client for the Domain service's internal endpoints.

Replaces the synchronous `app.send_task('domain.*', ...).get()` Celery RPC with a
direct, bounded HTTP call to the Domain service. Reads configuration from Django
settings:

    DOMAIN_INTERNAL_URL    base URL of Domain's API, e.g. "http://gaius-domain:8000/api/v2/domain/"
    DOMAIN_SERVICE_TOKEN   DRF token of the service (admin) user used to authenticate
    DOMAIN_HTTP_TIMEOUT    optional, seconds (default 10)

Each function mirrors the response shape of the Celery task it replaces, so
callers can swap `send_task(...).get()` for these one-for-one.
"""
import logging
from urllib.parse import urljoin

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10


class DomainClientError(Exception):
    """Raised when a call to the Domain internal API fails (transport or HTTP error)."""


def _base_url():
    url = getattr(settings, "DOMAIN_INTERNAL_URL", None)
    if not url:
        raise DomainClientError("DOMAIN_INTERNAL_URL is not configured")
    return url if url.endswith("/") else url + "/"


def _get(path, params=None):
    url = urljoin(_base_url(), path)
    token = getattr(settings, "DOMAIN_SERVICE_TOKEN", "")
    timeout = getattr(settings, "DOMAIN_HTTP_TIMEOUT", DEFAULT_TIMEOUT)
    try:
        resp = requests.get(
            url,
            params=params or {},
            headers={
                "Authorization": f"Token {token}",
                # In-cluster calls are plain HTTP, but the service runs
                # SECURE_SSL_REDIRECT=True. Assert the request is already
                # "secure" (the service trusts X-Forwarded-Proto via
                # SECURE_PROXY_SSL_HEADER) so it isn't 301-redirected to https.
                "X-Forwarded-Proto": "https",
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        logger.error("Domain API call failed: GET %s params=%s err=%s", url, params, e)
        raise DomainClientError(str(e)) from e


def get_subscription_by_domain(domain):
    """Replaces `domain.get_subscription_by_domain`.

    Returns the subscription dict for the route serving ``domain``, or ``None``
    when there is no matching route (the task answers HTTP 200 + ``null`` for
    that case, matching the old Celery RPC's falsy return).
    """
    return _get("internal/subscription-by-domain/", {"domain": domain})


def fetch_domain_info(hostname, cname, shadow):
    """Replaces `domain.fetch_domain_info`. Returns the rendered domain-info HTML
    string (or ``""`` when the route can't be resolved)."""
    return _get(
        "internal/domain-info/",
        {"hostname": hostname, "cname": cname, "shadow": shadow},
    )
