# keymgmt/services.py
# -------------------
# Key Management Module — handles key generation, storage, and rotation.
# All wrapping uses RSA (asymmetric) — no symmetric encryption used.

from .models import KeyEnvelope
from secureapp.rsa_scratch import (
    generate_rsa_keypair,
    rsa_encrypt, rsa_decrypt,
    serialize_public_key, deserialize_public_key,
    serialize_private_key, deserialize_private_key,
)
import base64
from django.conf import settings


def _get_server_pub():
    from secureapp.server_keys import get_server_keys
    pub, _ = get_server_keys()
    return pub

def _get_server_priv():
    from secureapp.server_keys import get_server_keys
    _, priv = get_server_keys()
    return priv


def create_key_envelope_for_user(user, *, kek_id=1, force=False):
    """
    Generate a per-user RSA key pair and store it.
    The user's RSA private key is wrapped (encrypted) using the
    server's RSA public key before being stored in KeyEnvelope.
    """
    if not force:
        try:
            return user.key_envelope
        except KeyEnvelope.DoesNotExist:
            pass

    user_pub, user_priv = generate_rsa_keypair(bits=1024)
    pub_bytes  = serialize_public_key(user_pub)
    priv_bytes = serialize_private_key(user_priv)

    # Wrap user private key with server RSA public key (asymmetric wrapping)
    server_pub = _get_server_pub()
    wrapped_priv = rsa_encrypt(priv_bytes, server_pub)

    env, _ = KeyEnvelope.objects.update_or_create(
        user=user,
        defaults={
            "wrapped_dek": wrapped_priv,   # stores RSA-wrapped private key
            "kek_id": kek_id,
        },
    )
    return env


def get_user_dek(user):
    """
    Retrieve and unwrap the user's RSA private key from KeyEnvelope.
    'dek' here is repurposed to mean the user's RSA private key bytes.
    """
    try:
        env = user.key_envelope
    except KeyEnvelope.DoesNotExist:
        env = create_key_envelope_for_user(user)

    server_priv = _get_server_priv()
    priv_bytes  = rsa_decrypt(bytes(env.wrapped_dek), server_priv)
    return priv_bytes