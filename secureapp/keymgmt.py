import base64, os
from django.conf import settings
from .crypto import wrap_dek_with_kek, unwrap_dek_with_kek

def get_kek() -> bytes:
    return base64.b64decode(settings.APP_KEK_BASE64.encode())

def generate_dek() -> bytes:
    return os.urandom(32)  # 256-bit AES key

def wrap_dek(dek: bytes) -> bytes:
    return wrap_dek_with_kek(dek, get_kek())

def unwrap_dek(wrapped: bytes) -> bytes:
    return unwrap_dek_with_kek(wrapped, get_kek())
