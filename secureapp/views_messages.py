from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password, check_password
from django.shortcuts import get_object_or_404, redirect, render
from django.core.mail import send_mail
from django.conf import settings

import random

from .crypto import (
    ecc_encrypt,
    ecc_decrypt,
    deserialize_ecc_public_key,
    deserialize_ecc_private_key,
)

from .mac import compute_mac, verify_mac

from .models import Message

from .server_keys import decrypt_with_server_key

Account = get_user_model()

# ── ECC Key Cache ─────────────────────────────────────────────

_key_cache = {}

def get_ecc_keys(user):

    cache_key = f"ecc_{user.id}"

    if cache_key not in _key_cache:

        pub = deserialize_ecc_public_key(
            bytes(user.ecc_public_key)
        )

        priv_raw = decrypt_with_server_key(
            bytes(user.ecc_private_key)
        )

        priv = deserialize_ecc_private_key(priv_raw)

        _key_cache[cache_key] = (pub, priv)

    return _key_cache[cache_key]


# ── OTP / 2FA ─────────────────────────────────────────────────

def generate_otp():

    return str(random.randint(100000, 999999))


def send_otp_email(to_email, otp):

    send_mail(
        subject="CipherMedia — Your Login OTP",

        message=(
            f"Your one-time login code is: {otp}\n\n"
            f"This code expires after one use."
        ),

        from_email=settings.DEFAULT_FROM_EMAIL,

        recipient_list=[to_email],

        fail_silently=False,
    )


def otp_verify_view(request):

    if request.method == "POST":

        entered_otp = request.POST.get("otp", "").strip()

        stored_otp = request.session.get("otp_code")

        user_id = request.session.get("otp_user_id")

        if not stored_otp or not user_id:

            messages.error(
                request,
                "Session expired. Please login again."
            )

            return redirect("login")

        if entered_otp == stored_otp:

            from django.contrib.auth import login

            user = Account.objects.get(id=user_id)

            login(
                request,
                user,
                backend="django.contrib.auth.backends.ModelBackend"
            )

            request.session.pop("otp_code", None)
            request.session.pop("otp_user_id", None)

            return redirect("index")

        else:

            messages.error(
                request,
                "Invalid OTP. Please try again."
            )

    from .forms import LoginForm

    return render(
        request,
        "registration/login.html",
        {
            "show_otp": True,
            "form": LoginForm()
        }
    )


# ── Message Vault ─────────────────────────────────────────────

@login_required
def vault_unlock_view(request):

    user = request.user

    has_pass = bool(user.message_password)

    if request.method == "POST":

        entered = request.POST.get(
            "vault_password",
            ""
        ).strip()

        if not has_pass:

            if len(entered) < 4:

                messages.error(
                    request,
                    "Password must be at least 4 characters."
                )

                return render(
                    request,
                    "messages_inbox.html",
                    {
                        "vault_locked": True,
                        "has_vault_pass": False
                    }
                )

            user.message_password = make_password(entered)

            user.save()

            request.session["vault_unlocked"] = True

            messages.success(
                request,
                "Vault password created."
            )

            return redirect("messages_inbox")

        else:

            if check_password(
                entered,
                user.message_password
            ):

                request.session["vault_unlocked"] = True

                return redirect("messages_inbox")

            else:

                messages.error(
                    request,
                    "Wrong vault password."
                )

                return render(
                    request,
                    "messages_inbox.html",
                    {
                        "vault_locked": True,
                        "has_vault_pass": True
                    }
                )

    return render(
        request,
        "messages_inbox.html",
        {
            "vault_locked": True,
            "has_vault_pass": has_pass
        }
    )


# ── Inbox ─────────────────────────────────────────────────────

@login_required
def messages_inbox_view(request):

    if not request.session.get("vault_unlocked"):

        return redirect("vault_unlock")

    user = request.user

    _, ecc_priv = get_ecc_keys(user)

    inbox = []

    for m in Message.objects.filter(
        recipient=user
    ).select_related("sender"):

        try:

            title = ecc_decrypt(
                bytes(m.title_ct),
                ecc_priv
            ).decode()

            mac_ok = True

            if m.mac:

                mac_key_raw = decrypt_with_server_key(
                    bytes(user.ecc_private_key)
                )

                mac_ok = verify_mac(
                    mac_key_raw,
                    bytes(m.title_ct) + bytes(m.body_ct),
                    bytes(m.mac)
                )

        except Exception:

            title = "[decrypt error]"

            mac_ok = False

        inbox.append({
            "id": m.id,

            "title": title,

            "from": (
                "Anonymous"
                if m.is_anonymous or not m.sender
                else m.sender.username
            ),

            "mac_ok": mac_ok,

            "created_at": m.created_at,
        })

    return render(
        request,
        "messages_inbox.html",
        {
            "inbox": inbox,
            "vault_locked": False
        }
    )


# ── Send Message ──────────────────────────────────────────────

@login_required
def message_new_view(request):

    if not request.session.get("vault_unlocked"):

        return redirect("vault_unlock")

    if request.method == "POST":

        to_username = request.POST.get("to", "").strip()

        title = request.POST.get("title", "").strip()

        body = request.POST.get("body", "").strip()

        anon = request.POST.get("anonymous") == "on"

        if not (to_username and title and body):

            messages.error(
                request,
                "All fields required."
            )

            return redirect("message_new")

        try:

            recipient = Account.objects.get(
                username=to_username
            )

        except Account.DoesNotExist:

            messages.error(
                request,
                "Recipient not found."
            )

            return redirect("message_new")

        if recipient.is_private:

            messages.error(
                request,
                f"{to_username}'s profile is private."
            )

            return redirect("message_new")

        ecc_pub, _ = get_ecc_keys(recipient)

        title_ct = ecc_encrypt(
            title.encode(),
            ecc_pub
        )

        body_ct = ecc_encrypt(
            body.encode(),
            ecc_pub
        )

        recip_priv_raw = decrypt_with_server_key(
            bytes(recipient.ecc_private_key)
        )

        mac = compute_mac(
            recip_priv_raw,
            title_ct + body_ct
        )

        Message.objects.create(
            recipient=recipient,

            sender=None if anon else request.user,

            is_anonymous=anon,

            title_ct=title_ct,

            body_ct=body_ct,

            mac=mac,
        )

        messages.success(
            request,
            f"Message sent to {to_username}."
        )

        return redirect("messages_inbox")

    return render(
        request,
        "message_new.html"
    )


# ── Message Detail ────────────────────────────────────────────

@login_required
def message_detail_view(request, msg_id):

    if not request.session.get("vault_unlocked"):

        return redirect("vault_unlock")

    m = get_object_or_404(
        Message,
        id=msg_id,
        recipient=request.user
    )

    user = request.user

    _, ecc_priv = get_ecc_keys(user)

    title = ecc_decrypt(
        bytes(m.title_ct),
        ecc_priv
    ).decode()

    body = ecc_decrypt(
        bytes(m.body_ct),
        ecc_priv
    ).decode()

    mac_ok = True

    if m.mac:

        ecc_priv_raw = decrypt_with_server_key(
            bytes(user.ecc_private_key)
        )

        mac_ok = verify_mac(
            ecc_priv_raw,
            bytes(m.title_ct) + bytes(m.body_ct),
            bytes(m.mac)
        )

    sender_name = (
        "Anonymous"
        if m.is_anonymous or not m.sender
        else m.sender.username
    )

    return render(
        request,
        "message_detail.html",
        {
            "title": title,
            "body": body,

            "from": sender_name,

            "mac_ok": mac_ok,

            "created_at": m.created_at,
        }
    )