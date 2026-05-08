import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def kdf_from_password(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def derive_key(password: str) -> tuple[bytes, bytes]:
    salt = os.urandom(16)
    return salt, kdf_from_password(password, salt)

def derive_key_with_salt(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())
