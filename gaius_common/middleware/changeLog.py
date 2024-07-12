import uuid
import socket
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

def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        return ip_address
    except OSError:
        return None

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