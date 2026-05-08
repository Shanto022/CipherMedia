from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings


class Account(AbstractUser):
    rsa_public_key  = models.BinaryField(null=True, blank=True)
    rsa_private_key = models.BinaryField(null=True, blank=True)
    ecc_public_key  = models.BinaryField(null=True, blank=True)
    ecc_private_key = models.BinaryField(null=True, blank=True)

    email_ct = models.BinaryField(null=True, blank=True)
    phone_ct = models.BinaryField(null=True, blank=True)

    ROLE_CHOICES = [("admin", "Admin"), ("user", "User")]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default="user")

    # Message Vault Password (hashed) — empty means not set yet
    message_password = models.CharField(max_length=255, blank=True, default="")
    is_private = models.BooleanField(default=False)
    profile_picture = models.BinaryField(null=True, blank=True)  # if True, no one can message this user


class Post(models.Model):
    user       = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title_ct   = models.BinaryField()
    body_ct    = models.BinaryField()
    mac        = models.BinaryField(null=True, blank=True)
    is_public  = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Post {self.id} by {self.user}"


class Message(models.Model):
    recipient    = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="inbox")
    sender       = models.ForeignKey(Account, null=True, blank=True, on_delete=models.SET_NULL, related_name="sent_messages")
    is_anonymous = models.BooleanField(default=False)
    title_ct     = models.BinaryField()
    body_ct      = models.BinaryField()
    mac          = models.BinaryField(null=True, blank=True)
    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]