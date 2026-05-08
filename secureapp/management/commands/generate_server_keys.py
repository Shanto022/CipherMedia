# generate_server_keys.py
# Run once: python manage.py generate_server_keys
# Copy the output into your .env file.

import base64
from django.core.management.base import BaseCommand
from secureapp.rsa_scratch import generate_rsa_keypair, serialize_public_key, serialize_private_key


class Command(BaseCommand):
    help = "Generate server RSA key pair for encrypting user private keys."

    def handle(self, *args, **opts):
        self.stdout.write("Generating 1024-bit server RSA key pair...")
        pub, priv = generate_rsa_keypair(bits=1024)

        pub_b64  = base64.b64encode(serialize_public_key(pub)).decode()
        priv_b64 = base64.b64encode(serialize_private_key(priv)).decode()

        self.stdout.write("\nAdd these lines to your .env file:\n")
        self.stdout.write(f"SERVER_RSA_PUBLIC_KEY={pub_b64}")
        self.stdout.write(f"SERVER_RSA_PRIVATE_KEY={priv_b64}")
        self.stdout.write("\nDone.")