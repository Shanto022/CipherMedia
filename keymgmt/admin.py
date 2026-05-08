from django.contrib import admin
from .models import KeyEnvelope

@admin.register(KeyEnvelope)
class KeyEnvelopeAdmin(admin.ModelAdmin):
    list_display = ("user", "wrapped_dek", "kek_id", "created_at", "rotated_at")
    search_fields = ("user__username",)
