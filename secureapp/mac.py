# mac.py
# HMAC-SHA256 implemented from scratch.
# HMAC formula: H((K XOR opad) || H((K XOR ipad) || message))
# We use Python's hashlib only for the SHA-256 hash function itself
# (SHA-256 is a hash, not an encryption algorithm).

import hashlib

BLOCK_SIZE = 64   # SHA-256 block size in bytes
IPAD = 0x36       # inner padding byte
OPAD = 0x5C       # outer padding byte


def _sha256(data: bytes) -> bytes:
    """Thin wrapper around SHA-256."""
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    HMAC-SHA256 from scratch.

    Steps:
      1. If key longer than block size, hash it first.
      2. Pad key to block size with zeros.
      3. inner = SHA256( (key XOR ipad) || message )
      4. outer = SHA256( (key XOR opad) || inner )
    """
    # Step 1: shorten long keys
    if len(key) > BLOCK_SIZE:
        key = _sha256(key)

    # Step 2: pad key to BLOCK_SIZE
    key = key.ljust(BLOCK_SIZE, b'\x00')

    # Step 3: inner hash
    ipad_key = bytes(b ^ IPAD for b in key)
    inner = _sha256(ipad_key + message)

    # Step 4: outer hash
    opad_key = bytes(b ^ OPAD for b in key)
    return _sha256(opad_key + inner)


def _safe_eq(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def compute_mac(key_bytes: bytes, data: bytes) -> bytes:
    return hmac_sha256(key_bytes[:32], data)


def verify_mac(key_bytes: bytes, data: bytes, expected: bytes) -> bool:
    actual = compute_mac(key_bytes, data)
    return _safe_eq(actual, expected)