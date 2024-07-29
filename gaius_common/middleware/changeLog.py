import uuid
import requests
from contextvars import ContextVar

_request_ctx = ContextVar('current_request', default={})

def set_current_request(new_context):
    _request_ctx.set(new_context)

def get_current_request():
    return _request_ctx.get()

def add_to_request_context(key, value):
    context = _request_ctx.get()
    context[key] = value
    _request_ctx.set(context)

_ip_cache = None
_IP_CHECK_URL = 'https://ifconfig.me/ip'

def get_ip_address():
    global _ip_cache
    if _ip_cache is None:
        try:
            # Use requests to fetch the public IP address
            response = requests.get(_IP_CHECK_URL)
            response.raise_for_status()
            _ip_cache = response.text.strip()
        except requests.RequestException:
            _ip_cache = "127.0.0.1"
    return _ip_cache

class ChangeLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Create a new dictionary for storing metadata
        request_metadata = {
            'request_id': str(uuid.uuid4()),
            'ip_address': get_ip_address(),
            'request': request  # Add the request object to the metadata
        }

        # Set the metadata context
        set_current_request(request_metadata)

        # Pass the original request object to the next middleware or view
        response = self.get_response(request)

        return response