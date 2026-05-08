"""
rsa_scratch.py
--------------
RSA encryption from scratch — no external crypto library used.
Implements:
  - Large prime generation (Miller-Rabin primality test)
  - RSA key pair generation
  - RSA encrypt / decrypt with OAEP-style padding (manual)
  - Chunked encrypt/decrypt so any length plaintext works
"""

import os
import random


# ──────────────────────────────────────────────
# PART 1: Math helpers
# ──────────────────────────────────────────────

def mod_pow(base, exp, mod):
    """
    Fast modular exponentiation: computes (base ^ exp) % mod
    This is the core math operation behind RSA.
    Python's built-in pow(base, exp, mod) does the same thing,
    but we write it out so you can see what's happening.
    """
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:          # if current bit is 1
            result = (result * base) % mod
        exp = exp >> 1            # shift right (divide by 2)
        base = (base * base) % mod
    return result


def gcd(a, b):
    """
    Euclidean algorithm — finds the Greatest Common Divisor.
    Used to check that e and phi(n) share no common factors.
    """
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """
    Extended Euclidean algorithm.
    Returns (g, x, y) such that: a*x + b*y = g = gcd(a, b)
    We use this to find the modular inverse of e.
    """
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(e, phi):
    """
    Finds d such that (e * d) % phi == 1.
    This d is the RSA private key exponent.
    Raises an error if the inverse does not exist.
    """
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError("Modular inverse does not exist — e and phi are not coprime.")
    return x % phi


# ──────────────────────────────────────────────
# PART 2: Prime number generation
# ──────────────────────────────────────────────

def miller_rabin(n, k=20):
    """
    Miller-Rabin probabilistic primality test.
    Returns True if n is (very likely) prime.
    k = number of test rounds — higher k = more certainty.

    How it works:
      Write n-1 as 2^r * d (factor out all 2s).
      For k random witnesses 'a', check if n behaves like a prime.
      If any witness says composite → definitely composite.
      If all witnesses pass → almost certainly prime.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Test with k random witnesses
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)

        if x == 1 or x == n - 1:
            continue  # this witness passes

        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # composite

    return True  # probably prime


def generate_large_prime(bits=1024):
    """
    Generates a random prime number of the given bit length.
    We keep generating random odd numbers until we find a prime.
    1024-bit primes are used so that n = p*q is 2048 bits.
    """
    while True:
        # Generate a random odd number of the right bit size
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))   # ensure it's exactly `bits` bits long
        candidate |= 1                    # ensure it's odd (even numbers can't be prime)

        if miller_rabin(candidate):
            return candidate


# ──────────────────────────────────────────────
# PART 3: RSA Key Generation
# ──────────────────────────────────────────────

def generate_rsa_keypair(bits=1024):
    """
    Generates an RSA public/private key pair.

    Steps:
      1. Pick two large primes p and q (each `bits` bits long).
      2. Compute n = p * q  (this is the RSA modulus).
      3. Compute phi(n) = (p-1) * (q-1).
      4. Choose e = 65537 (a standard public exponent).
      5. Compute d = modular_inverse(e, phi(n)).

    Public key  = (e, n)  — used to ENCRYPT.
    Private key = (d, n)  — used to DECRYPT.

    Returns:
      public_key  = (e, n)   as a dict
      private_key = (d, n)   as a dict
    """
    print("[RSA] Generating primes... (this may take a few seconds)")

    # Step 1: Generate two distinct primes
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    while q == p:                          # make sure they're different
        q = generate_large_prime(bits)

    # Step 2: Compute modulus
    n = p * q

    # Step 3: Euler's totient
    phi_n = (p - 1) * (q - 1)

    # Step 4: Public exponent (65537 is standard — it's prime and fast)
    e = 65537
    if gcd(e, phi_n) != 1:
        # Very rare — just regenerate
        return generate_rsa_keypair(bits)

    # Step 5: Private exponent
    d = mod_inverse(e, phi_n)

    public_key  = {"e": e, "n": n}
    private_key = {"d": d, "n": n}

    return public_key, private_key


# ──────────────────────────────────────────────
# PART 4: Simple padding helpers
# ──────────────────────────────────────────────
# Real OAEP uses SHA hashing for the mask.
# Here we use a lightweight deterministic padding so
# we can detect decrypt errors without a heavy library.

_PADDING_HEADER = b"\x00\x02"   # marks the start of a padded block
_PADDING_SEP    = b"\x00"       # separates padding from message

def _pad(message_bytes, block_size):
    """
    Adds simple PKCS#1 v1.5 -style padding to fill a block.
    block_size = number of BYTES in the RSA modulus n.

    Format: 0x00 | 0x02 | <random non-zero bytes> | 0x00 | <message>
    """
    msg_len  = len(message_bytes)
    # How many random padding bytes do we need?
    pad_len  = block_size - msg_len - len(_PADDING_HEADER) - len(_PADDING_SEP)
    if pad_len < 8:
        raise ValueError(f"Message too long for this block size ({msg_len} bytes).")

    # Random bytes — no zeros allowed in the padding region
    padding = bytes([random.randint(1, 255) for _ in range(pad_len)])
    return _PADDING_HEADER + padding + _PADDING_SEP + message_bytes


def _unpad(padded_bytes):
    """
    Removes padding and returns the original message bytes.
    Raises ValueError if the format is wrong (tampered data).
    """
    if not padded_bytes.startswith(_PADDING_HEADER):
        raise ValueError("Bad padding header — decryption may have failed or data is corrupt.")
    # Find the 0x00 separator after the random padding
    sep_index = padded_bytes.index(_PADDING_SEP, len(_PADDING_HEADER))
    return padded_bytes[sep_index + len(_PADDING_SEP):]


# ──────────────────────────────────────────────
# PART 5: Single-block RSA encrypt / decrypt
# ──────────────────────────────────────────────

def _rsa_encrypt_block(plaintext_bytes, public_key):
    """
    Encrypts ONE block of bytes using the RSA public key.
    plaintext_bytes must be shorter than the key modulus.
    """
    e, n = public_key["e"], public_key["n"]
    block_size = (n.bit_length() + 7) // 8     # byte length of n

    padded   = _pad(plaintext_bytes, block_size)
    m_int    = int.from_bytes(padded, "big")    # bytes → integer
    c_int    = mod_pow(m_int, e, n)             # c = m^e mod n
    return c_int.to_bytes(block_size, "big")    # integer → bytes


def _rsa_decrypt_block(ciphertext_bytes, private_key):
    """
    Decrypts ONE block of bytes using the RSA private key.
    """
    d, n = private_key["d"], private_key["n"]
    block_size = (n.bit_length() + 7) // 8

    c_int    = int.from_bytes(ciphertext_bytes, "big")   # bytes → integer
    m_int    = mod_pow(c_int, d, n)                       # m = c^d mod n
    padded   = m_int.to_bytes(block_size, "big")          # integer → bytes
    return _unpad(padded)


# ──────────────────────────────────────────────
# PART 6: Chunked encrypt / decrypt (handles ANY length)
# ──────────────────────────────────────────────
# RSA can only encrypt data smaller than the key modulus.
# For a 1024-bit key, the modulus is 128 bytes, so we can
# safely encrypt at most ~100 bytes per block.
# We split long messages into chunks and encrypt each one.

_CHUNK_SIZE = 86   # safe chunk size for 1024-bit keys with our padding

def rsa_encrypt(plaintext_bytes: bytes, public_key: dict) -> bytes:
    """
    Encrypts arbitrary-length bytes using RSA (chunked).

    Returns:
      A bytes object containing all encrypted chunks concatenated.
      Each chunk is exactly block_size bytes long.
    """
    n = public_key["n"]
    block_size = (n.bit_length() + 7) // 8

    ciphertext_parts = []
    # Split into chunks and encrypt each one
    for i in range(0, len(plaintext_bytes), _CHUNK_SIZE):
        chunk = plaintext_bytes[i : i + _CHUNK_SIZE]
        encrypted_chunk = _rsa_encrypt_block(chunk, public_key)
        ciphertext_parts.append(encrypted_chunk)

    # Prefix with 4 bytes = number of chunks (so we know how to split on decrypt)
    num_chunks = len(ciphertext_parts)
    header = num_chunks.to_bytes(4, "big")
    return header + b"".join(ciphertext_parts)


def rsa_decrypt(ciphertext_bytes: bytes, private_key: dict) -> bytes:
    """
    Decrypts bytes produced by rsa_encrypt().
    Reads the chunk count from the header, then decrypts each chunk.
    """
    n = private_key["n"]
    block_size = (n.bit_length() + 7) // 8

    # Read header
    num_chunks = int.from_bytes(ciphertext_bytes[:4], "big")
    data       = ciphertext_bytes[4:]

    plaintext_parts = []
    for i in range(num_chunks):
        chunk = data[i * block_size : (i + 1) * block_size]
        decrypted_chunk = _rsa_decrypt_block(chunk, private_key)
        plaintext_parts.append(decrypted_chunk)

    return b"".join(plaintext_parts)


# ──────────────────────────────────────────────
# PART 7: Key serialization (save/load as bytes)
# ──────────────────────────────────────────────
# We need to store keys in the database as bytes.
# We encode the big integers as hex strings separated by "|".

def serialize_public_key(public_key: dict) -> bytes:
    """Converts public key (e, n) to bytes for storage."""
    e_hex = hex(public_key["e"])
    n_hex = hex(public_key["n"])
    return f"{e_hex}|{n_hex}".encode("utf-8")


def deserialize_public_key(data: bytes) -> dict:
    """Loads public key (e, n) from stored bytes."""
    e_hex, n_hex = data.decode("utf-8").split("|")
    return {"e": int(e_hex, 16), "n": int(n_hex, 16)}


def serialize_private_key(private_key: dict) -> bytes:
    """Converts private key (d, n) to bytes for storage."""
    d_hex = hex(private_key["d"])
    n_hex = hex(private_key["n"])
    return f"{d_hex}|{n_hex}".encode("utf-8")


def deserialize_private_key(data: bytes) -> dict:
    """Loads private key (d, n) from stored bytes."""
    d_hex, n_hex = data.decode("utf-8").split("|")
    return {"d": int(d_hex, 16), "n": int(n_hex, 16)}


# ──────────────────────────────────────────────
# Quick self-test (run this file directly to verify)
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=== RSA From Scratch — Self Test ===\n")

    print("Step 1: Generating 1024-bit RSA key pair...")
    pub, priv = generate_rsa_keypair(bits=1024)
    print(f"  Public key  e = {pub['e']}")
    print(f"  Modulus   n = {pub['n'].bit_length()} bits\n")

    # Test short message
    message = b"Hello ciphermedia!"
    print(f"Step 2: Encrypting: {message}")
    ct = rsa_encrypt(message, pub)
    print(f"  Ciphertext ({len(ct)} bytes): {ct[:32].hex()}...")

    pt = rsa_decrypt(ct, priv)
    print(f"  Decrypted: {pt}")
    assert pt == message, "FAIL: decrypted text doesn't match!"
    print("  [OK] Short message passed.\n")

    # Test long message
    long_msg = b"A" * 300
    print(f"Step 3: Encrypting long message (300 bytes)...")
    ct2 = rsa_encrypt(long_msg, pub)
    pt2 = rsa_decrypt(ct2, priv)
    assert pt2 == long_msg, "FAIL: long message test!"
    print("  [OK] Long message passed.\n")

    # Test serialization
    print("Step 4: Testing key serialization...")
    pub_bytes  = serialize_public_key(pub)
    priv_bytes = serialize_private_key(priv)
    pub2  = deserialize_public_key(pub_bytes)
    priv2 = deserialize_private_key(priv_bytes)
    ct3 = rsa_encrypt(b"serialize test", pub2)
    pt3 = rsa_decrypt(ct3, priv2)
    assert pt3 == b"serialize test", "FAIL: serialization test!"
    print("  [OK] Serialization passed.\n")

    print("=== All tests passed! ===")