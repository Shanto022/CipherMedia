# admin.py
# -
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Account, Post, Message


def _hex_preview(b):
     
    if not b:
        return "—"
    try:
        return bytes(b)[:12].hex() + "…"
    except Exception:
        return "—"


@admin.register(Account)
class AccountAdmin(UserAdmin):
    list_display  = ("username", "role", "is_active", "is_staff", "date_joined", "email_preview", "phone_preview")
    list_filter   = ("is_active", "is_staff", "role")
    search_fields = ("username",)

    fieldsets = UserAdmin.fieldsets + (
        ("Keys", {
            "fields": ("role", "rsa_public_key", "rsa_private_key", "ecc_public_key", "ecc_private_key")
        }),
        ("Encrypted PII", {
            "fields": ("email_ct", "phone_ct")
        }),
    )

    @admin.display(description="Email (preview)")
    def email_preview(self, obj):
        return _hex_preview(obj.email_ct)

    @admin.display(description="Phone (preview)")
    def phone_preview(self, obj):
        return _hex_preview(obj.phone_ct)


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display  = ("id", "user", "is_public", "created_at", "title_preview")
    list_filter   = ("is_public", "created_at")
    search_fields = ("user__username",)

    @admin.display(description="Title (cipher preview)")
    def title_preview(self, obj):
        return _hex_preview(obj.title_ct)


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display  = ("id", "recipient", "sender", "is_anonymous", "created_at", "title_preview")
    list_filter   = ("is_anonymous", "created_at")
    search_fields = ("recipient__username", "sender__username")

    @admin.display(description="Title (cipher preview)")
    def title_preview(self, obj):
        return _hex_preview(obj.title_ct)