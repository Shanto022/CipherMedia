# crypto.py


# RSA functions (posts and PII encrypt kore)
from .rsa_scratch import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    serialize_public_key,
    deserialize_public_key,
    serialize_private_key,
    deserialize_private_key,
)

# ECC functions (messages encrypt)
from .ecc_scratch import (
    generate_ecc_keypair,
    ecc_encrypt,
    ecc_decrypt,
    serialize_ecc_public_key,
    deserialize_ecc_public_key,
    serialize_ecc_private_key,
    deserialize_ecc_private_key,
)