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

def get_ip_address(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class ChangeLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Create a new dictionary for storing metadata
        request_metadata = {
            'request_id': str(uuid.uuid4()),
            'ip_address': get_ip_address(request),
            'request': request  # Add the request object to the metadata
        }

        # Set the metadata context
        set_current_request(request_metadata)

        # Pass the original request object to the next middleware or view
        response = self.get_response(request)

        return response