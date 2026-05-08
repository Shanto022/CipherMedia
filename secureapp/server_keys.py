# server_keys.py
# --------------
# Server-level RSA master key used to encrypt user private keys before DB storage.
# This ensures private keys are NEVER stored in plaintext.
#
# How it works:
#   - A server RSA key pair is generated once and stored in .env
#   - User RSA private key  → encrypted with server RSA public key → stored in DB
#   - User ECC private key  → encrypted with server RSA public key → stored in DB
#   - On load: decrypt with server RSA private key to get user key back

import os
import base64
from django.conf import settings
from .rsa_scratch import (
    generate_rsa_keypair,
    rsa_encrypt, rsa_decrypt,
    serialize_public_key, deserialize_public_key,
    serialize_private_key, deserialize_private_key,
)


def get_server_keys():
    """Load server RSA key pair from settings (originally from .env)."""
    pub_b64  = getattr(settings, "SERVER_RSA_PUBLIC_KEY",  None)
    priv_b64 = getattr(settings, "SERVER_RSA_PRIVATE_KEY", None)

    if not pub_b64 or not priv_b64:
        raise RuntimeError(
            "SERVER_RSA_PUBLIC_KEY and SERVER_RSA_PRIVATE_KEY must be set in .env. "
            "Run: python manage.py generate_server_keys"
        )

    pub  = deserialize_public_key(base64.b64decode(pub_b64))
    priv = deserialize_private_key(base64.b64decode(priv_b64))
    return pub, priv


def encrypt_with_server_key(plaintext_bytes: bytes) -> bytes:
    """Encrypt bytes using the server RSA public key."""
    pub, _ = get_server_keys()
    return rsa_encrypt(plaintext_bytes, pub)


def decrypt_with_server_key(ciphertext_bytes: bytes) -> bytes:
    """Decrypt bytes using the server RSA private key."""
    _, priv = get_server_keys()
    return rsa_decrypt(ciphertext_bytes, priv)