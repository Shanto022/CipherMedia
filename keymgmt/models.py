# keymgmt/models.py
from django.db import models
from django.conf import settings

class KeyEnvelope(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="key_envelope",
    )
    wrapped_dek = models.BinaryField()
    kek_id = models.IntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    rotated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "key_envelopes"
