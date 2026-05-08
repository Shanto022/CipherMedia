"""
ecc_scratch.py
--------------
Elliptic Curve Cryptography (ECC) from scratch — no external crypto library used.
Uses the standard NIST P-256 curve.
Implements:
  - Elliptic curve point math (add, double, multiply)
  - ECC key pair generation
  - EC ElGamal-style encrypt / decrypt
  - Key serialization for database storage
"""

import os
import random


# ──────────────────────────────────────────────
# PART 1: P-256 Curve Parameters (official NIST values)
# ──────────────────────────────────────────────
# The curve equation is:  y² = x³ + ax + b  (mod P)
# All arithmetic is done modulo the prime P.

P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
B  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

G = (GX, GY)   # Generator point — the "starting point" everyone agrees on


# ──────────────────────────────────────────────
# PART 2: Point operations on the curve
# ──────────────────────────────────────────────

def point_add(P1, P2):
    """
    Adds two points on the elliptic curve.
    None represents the "point at infinity" (the identity element, like zero).
    """
    if P1 is None:
        return P2
    if P2 is None:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2:
        if y1 != y2:
            return None          # P + (-P) = point at infinity
        return point_double(P1)  # P + P = 2P

    # Slope of the line through P1 and P2
    m  = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def point_double(P1):
    """
    Doubles a point (adds it to itself).
    Used inside scalar_multiply for efficiency.
    """
    if P1 is None:
        return None

    x1, y1 = P1

    # Tangent slope at the point
    m  = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    x3 = (m * m - 2 * x1) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_multiply(k, point):
    """
    Computes k * point using the double-and-add algorithm.
    This is the main operation in ECC.

    Example: 5 * G = G + G + G + G + G
    But instead of adding G five times, we do it in log2(k) steps.
    """
    result = None    # Start at point at infinity
    addend = point

    while k > 0:
        if k & 1:                          # if the lowest bit is 1
            result = point_add(result, addend)
        addend = point_double(addend)      # double each step
        k >>= 1                            # move to next bit

    return result


# ──────────────────────────────────────────────
# PART 3: Key generation
# ──────────────────────────────────────────────

def generate_ecc_keypair():
    """
    Generates an ECC public/private key pair.

    Private key = a random number d  (keep this secret!)
    Public key  = d * G              (share this with everyone)

    It's impossible to recover d from (d*G) — this is the
    'elliptic curve discrete logarithm problem'.

    Returns:
      public_key  = (x, y) point on the curve
      private_key = integer d
    """
    d = random.randint(2, N - 1)   # random private key
    Q = scalar_multiply(d, G)      # public key = d * G
    return Q, d


# ──────────────────────────────────────────────
# PART 4: Keystream derivation from a shared point
# ──────────────────────────────────────────────

def _point_to_keystream(shared_point, length):
    """
    Turns a shared EC point into a keystream of `length` bytes.

    We take the x and y coordinates of the point, convert them
    to bytes, then repeat/extend them to cover the full message length.
    This is how ECDH turns a shared point into usable key material.

    No hashing library is used — we just use raw coordinate bytes
    combined in a repeating pattern.
    """
    x, y = shared_point
    # Convert both coordinates to 32-byte big-endian integers
    seed = x.to_bytes(32, "big") + y.to_bytes(32, "big")   # 64 bytes
    keystream = bytearray()
    counter   = 0
    while len(keystream) < length:
        # Mix counter into each 64-byte block to avoid repetition
        block = bytearray(seed)
        for i in range(8):
            block[i] ^= (counter >> (8 * i)) & 0xFF
        keystream += block
        counter   += 1
    return bytes(keystream[:length])


# ──────────────────────────────────────────────
# PART 5: ECC Encrypt / Decrypt
# ──────────────────────────────────────────────
# This is EC ElGamal / ECIES-style encryption.
#
# How it works:
#   Encrypt(message, recipient_public_key Q):
#     1. Pick a random scalar r
#     2. Compute R = r * G          (ephemeral public key)
#     3. Compute S = r * Q          (shared secret point)
#     4. keystream = expand(S, len(message))
#     5. ciphertext = message XOR keystream
#     6. Send (R, ciphertext)
#
#   Decrypt(R, ciphertext, private_key d):
#     1. Compute S = d * R          (= d * r * G = r * (d*G) = r*Q ✓)
#     2. keystream = expand(S, len(ciphertext))
#     3. message = ciphertext XOR keystream

def ecc_encrypt(plaintext_bytes: bytes, public_key: tuple) -> bytes:
    """
    Encrypts arbitrary bytes using the recipient's ECC public key.

    Returns bytes in the format:
      [4 bytes: len of R_x] [R_x bytes] [R_y bytes] [ciphertext bytes]
    """
    Q = public_key   # recipient's public key point

    # Step 1 & 2: ephemeral key pair
    r = random.randint(2, N - 1)
    R = scalar_multiply(r, G)

    # Step 3: shared secret
    S = scalar_multiply(r, Q)

    # Step 4: keystream
    keystream = _point_to_keystream(S, len(plaintext_bytes))

    # Step 5: XOR to get ciphertext
    ciphertext = bytes(a ^ b for a, b in zip(plaintext_bytes, keystream))

    # Serialize R and ciphertext together
    Rx_bytes = R[0].to_bytes(32, "big")
    Ry_bytes = R[1].to_bytes(32, "big")

    # Format: [32 bytes Rx][32 bytes Ry][ciphertext]
    return Rx_bytes + Ry_bytes + ciphertext


def ecc_decrypt(encrypted_bytes: bytes, private_key: int) -> bytes:
    """
    Decrypts bytes produced by ecc_encrypt() using the ECC private key.
    """
    d = private_key

    # Parse R point and ciphertext from the blob
    Rx = int.from_bytes(encrypted_bytes[0:32],  "big")
    Ry = int.from_bytes(encrypted_bytes[32:64], "big")
    R  = (Rx, Ry)

    ciphertext = encrypted_bytes[64:]

    # Step 1: recompute shared secret
    S = scalar_multiply(d, R)

    # Step 2: keystream
    keystream = _point_to_keystream(S, len(ciphertext))

    # Step 3: XOR to recover plaintext
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
    return plaintext


# ──────────────────────────────────────────────
# PART 6: Key serialization (save/load as bytes)
# ──────────────────────────────────────────────

def serialize_ecc_public_key(public_key: tuple) -> bytes:
    """Converts ECC public key (x, y) to bytes for database storage."""
    x, y = public_key
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")   # 64 bytes total


def deserialize_ecc_public_key(data: bytes) -> tuple:
    """Loads ECC public key from stored bytes."""
    x = int.from_bytes(data[0:32], "big")
    y = int.from_bytes(data[32:64], "big")
    return (x, y)


def serialize_ecc_private_key(private_key: int) -> bytes:
    """Converts ECC private key (integer) to bytes for database storage."""
    return private_key.to_bytes(32, "big")


def deserialize_ecc_private_key(data: bytes) -> int:
    """Loads ECC private key from stored bytes."""
    return int.from_bytes(data, "big")


# ──────────────────────────────────────────────
# Quick self-test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=== ECC From Scratch — Self Test ===\n")

    print("Step 1: Generating ECC key pair...")
    pub, priv = generate_ecc_keypair()
    print(f"  Public key x = {hex(pub[0])[:20]}...")
    print(f"  Private key  = {hex(priv)[:20]}...\n")

    # Short message
    msg = b"Hello ECC!"
    print(f"Step 2: Encrypting: {msg}")
    ct = ecc_encrypt(msg, pub)
    print(f"  Ciphertext ({len(ct)} bytes): {ct[:16].hex()}...")
    pt = ecc_decrypt(ct, priv)
    print(f"  Decrypted: {pt}")
    assert pt == msg, "FAIL!"
    print("  [OK]\n")

    # Long message
    long_msg = b"X" * 500
    print("Step 3: Long message (500 bytes)...")
    ct2 = ecc_encrypt(long_msg, pub)
    pt2 = ecc_decrypt(ct2, priv)
    assert pt2 == long_msg, "FAIL!"
    print("  [OK]\n")

    # Serialization
    print("Step 4: Serialization test...")
    pub_b  = serialize_ecc_public_key(pub)
    priv_b = serialize_ecc_private_key(priv)
    pub2   = deserialize_ecc_public_key(pub_b)
    priv2  = deserialize_ecc_private_key(priv_b)
    ct3 = ecc_encrypt(b"serialize ok", pub2)
    pt3 = ecc_decrypt(ct3, priv2)
    assert pt3 == b"serialize ok", "FAIL!"
    print("  [OK]\n")

    print("=== All tests passed! ===")