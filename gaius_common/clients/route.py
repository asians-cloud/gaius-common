"""HTTP client for the Route service's internal endpoints.

Replaces the synchronous `app.send_task('jumpserver.tasks.*', ...).get()` Celery
RPC with a direct, bounded HTTP call to the Route service. Reads configuration
from Django settings:

    ROUTE_INTERNAL_URL    base URL of Route's API, e.g. "http://gaius-route:8000/api/v3/"
    ROUTE_SERVICE_TOKEN   DRF token of the service (admin) user used to authenticate
    ROUTE_HTTP_TIMEOUT    optional, seconds (default 10)

Each function mirrors the response shape of the Celery task it replaces, so
callers can swap `send_task(...).get()` for these one-for-one.
"""

import logging
from urllib.parse import urljoin

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10


class RouteClientError(Exception):
    """Raised when a call to the Route internal API fails (transport or HTTP error)."""


def _base_url():
    url = getattr(settings, "ROUTE_INTERNAL_URL", None)
    if not url:
        raise RouteClientError("ROUTE_INTERNAL_URL is not configured")
    return url if url.endswith("/") else url + "/"


def _get(path, params=None):
    url = urljoin(_base_url(), path)
    token = getattr(settings, "ROUTE_SERVICE_TOKEN", "")
    timeout = getattr(settings, "ROUTE_HTTP_TIMEOUT", DEFAULT_TIMEOUT)
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
        logger.error("Route API call failed: GET %s params=%s err=%s", url, params, e)
        raise RouteClientError(str(e)) from e


def get_jumpserver_by_node(node):
    """Replaces `jumpserver.tasks.get_jumpserver_by_node`.

    Returns a list of Jumpserver asset dicts matching ``node`` (each with a
    ``nodes_display`` list); an empty list when no asset matches, matching the
    old Celery RPC's return.
    """
    return _get("internal/jumpserver-by-node/", {"node": node})
