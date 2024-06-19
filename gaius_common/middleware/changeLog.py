import uuid
import socket
from contextvars import ContextVar

_request_ctx = ContextVar('current_request', default=None)

def get_current_request():
    return _request_ctx.get()

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
        request.request_id = str(uuid.uuid4())
        request.ip_address = get_ip_address()
        _request_ctx.set(request)
        response = self.get_response(request)
        return response
