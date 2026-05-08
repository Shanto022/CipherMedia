import base64, os
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.contrib.auth import get_user_model
from keymgmt.models import KeyEnvelope
from keymgmt.services import unwrap_dek, wrap_dek, get_active_kek
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from keymgmt.services import get_active_kek, unwrap_dek, wrap_dek, generate_dek
from keymgmt.models import KeyEnvelope
from secureapp.crypto import aead_decrypt, aead_encrypt

class Command(BaseCommand):
    help = "Rotate KEK: rewrap all user DEKs from current KEK to a new KEK (base64)."

    def add_arguments(self, parser):
        parser.add_argument("--new-kek-b64", required=True, help="Base64-encoded new KEK bytes")
        parser.add_argument("--new-kek-id", type=int, required=True, help="Integer ID for the new KEK")

    def handle(self, *args, **opts):
        new_b64 = opts["new_kek_b64"]
        new_kek_id = opts["new_kek_id"]
        try:
            new_kek = base64.b64decode(new_b64)
        except Exception as e:
            raise CommandError(f"Invalid new kek b64: {e}")
        if len(new_kek) not in (16, 24, 32):
            raise CommandError("New KEK must be 16/24/32 bytes after base64 decode")

        old_kek_id, old_kek = get_active_kek()
        total = 0

        for env in KeyEnvelope.objects.select_related("user").all():
            # unwrap with old, wrap with new
            dek = unwrap_dek(env.wrapped_dek, old_kek)
            env.wrapped_dek = wrap_dek(dek, new_kek)
            env.kek_id = new_kek_id
            env.save(update_fields=["wrapped_dek", "kek_id"])
            total += 1

        self.stdout.write(self.style.SUCCESS(
            f"Rewrapped {total} user DEKs from KEK {old_kek_id} to KEK {new_kek_id}. "
            "Remember to update .env: KEYMGMT_ACTIVE_KEK_ID and APP_KEK_BASE64"
        ))
        _, kek = get_active_kek()
        Account = get_user_model()
        total = 0
        for u in Account.objects.all():
            env = u.key_envelope
            old_dek = unwrap_dek(env.wrapped_dek, kek)

            # decrypt existing data
            email = aead_decrypt(old_dek, u.email_nonce, u.email_ct, b"users.email") if u.email_ct else b""
            phone = aead_decrypt(old_dek, u.phone_nonce, u.phone_ct, b"users.phone") if u.phone_ct else b""
            priv = aead_decrypt(old_dek, u.privkey_nonce, u.privkey_ct, b"user.private_key") if u.privkey_ct else b""

            # new DEK
            new_dek = generate_dek()
            env.wrapped_dek = wrap_dek(new_dek, kek)
            env.save()

            # re-encrypt
            if email:
                u.email_nonce, u.email_ct = aead_encrypt(new_dek, email, b"users.email")
            if phone:
                u.phone_nonce, u.phone_ct = aead_encrypt(new_dek, phone, b"users.phone")
            if priv:
                u.privkey_nonce, u.privkey_ct = aead_encrypt(new_dek, priv, b"user.private_key")
            u.save()
            total += 1
        self.stdout.write(self.style.SUCCESS(f"Rotated DEKs for {total} users."))
