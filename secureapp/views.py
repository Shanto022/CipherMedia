from django.contrib import messages
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password, check_password
from django.shortcuts import get_object_or_404, redirect, render
from django.core.mail import send_mail
from django.conf import settings
import random

from .crypto import (
    generate_rsa_keypair, rsa_encrypt, rsa_decrypt,
    serialize_public_key, deserialize_public_key,
    serialize_private_key, deserialize_private_key,
    generate_ecc_keypair, ecc_encrypt, ecc_decrypt,
    serialize_ecc_public_key, deserialize_ecc_public_key,
    serialize_ecc_private_key, deserialize_ecc_private_key,
)
from .mac import compute_mac, verify_mac
from .forms import LoginForm, RegisterForm
from .models import Message, Post
from .auth_utils import check_credentials
from .steganography import hide_message, extract_message
from .server_keys import encrypt_with_server_key, decrypt_with_server_key

Account = get_user_model()


# ── Helpers ───────────────────────────────────────────────────

# In-memory cache per process — avoids repeated RSA decrypts in same request
_key_cache = {}

def get_rsa_keys(user):
    cache_key = f"rsa_{user.id}"
    if cache_key not in _key_cache:
        pub      = deserialize_public_key(bytes(user.rsa_public_key))
        priv_raw = decrypt_with_server_key(bytes(user.rsa_private_key))
        priv     = deserialize_private_key(priv_raw)
        _key_cache[cache_key] = (pub, priv)
    return _key_cache[cache_key]

def get_ecc_keys(user):
    cache_key = f"ecc_{user.id}"
    if cache_key not in _key_cache:
        pub      = deserialize_ecc_public_key(bytes(user.ecc_public_key))
        priv_raw = decrypt_with_server_key(bytes(user.ecc_private_key))
        priv     = deserialize_ecc_private_key(priv_raw)
        _key_cache[cache_key] = (pub, priv)
    return _key_cache[cache_key]

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(to_email, otp):
    send_mail(
        subject="CipherMedia — Your Login OTP",
        message=f"Your one-time login code is: {otp}\n\nThis code expires after one use.",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[to_email],
        fail_silently=False,
    )


# ── Registration ──────────────────────────────────────────────

def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            username    = form.cleaned_data["username"].strip()
            password    = form.cleaned_data["password1"]
            email_plain = form.cleaned_data["email"].strip()
            phone_plain = form.cleaned_data["phone"].strip()

            user = Account.objects.create_user(username=username, password=password)
            try:
                rsa_pub, rsa_priv = generate_rsa_keypair(bits=1024)
                user.rsa_public_key  = serialize_public_key(rsa_pub)
                # Encrypt RSA private key with server RSA public key before storing
                user.rsa_private_key = encrypt_with_server_key(serialize_private_key(rsa_priv))

                ecc_pub, ecc_priv = generate_ecc_keypair()
                user.ecc_public_key  = serialize_ecc_public_key(ecc_pub)
                # Encrypt ECC private key with server RSA public key before storing
                user.ecc_private_key = encrypt_with_server_key(serialize_ecc_private_key(ecc_priv))

                user.email_ct = rsa_encrypt(email_plain.encode(), rsa_pub)
                user.phone_ct = rsa_encrypt(phone_plain.encode(), rsa_pub)
                user.save()
            except Exception as e:
                user.delete()
                messages.error(request, f"Registration failed: {e}")
                return redirect("register")

            messages.success(request, "Registered! Please login.")
            return redirect("login")
    else:
        form = RegisterForm()
    return render(request, "register.html", {"form": form})


# ── Login Step 1 ──────────────────────────────────────────────

def login_view(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            user = check_credentials(
                form.cleaned_data["username"].strip(),
                form.cleaned_data["password"],
            )
            if user:
                rsa_pub, rsa_priv = get_rsa_keys(user)
                user_email = rsa_decrypt(bytes(user.email_ct), rsa_priv).decode()

                otp = generate_otp()
                try:
                    send_otp_email(user_email, otp)
                except Exception:
                    messages.error(request, "Could not send OTP email. Check email settings.")
                    return redirect("login")

                request.session["otp_code"]    = otp
                request.session["otp_user_id"] = user.id
                messages.success(request, f"OTP sent to {user_email}")
                return redirect("otp_verify")

            messages.error(request, "Invalid username or password.")
    else:
        form = LoginForm()
    return render(request, "registration/login.html", {"form": form})


# ── Login Step 2: OTP ─────────────────────────────────────────

def otp_verify_view(request):
    if request.method == "POST":
        entered_otp = request.POST.get("otp", "").strip()
        stored_otp  = request.session.get("otp_code")
        user_id     = request.session.get("otp_user_id")

        if not stored_otp or not user_id:
            messages.error(request, "Session expired. Please login again.")
            return redirect("login")

        if entered_otp == stored_otp:
            user = Account.objects.get(id=user_id)
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            request.session.pop("otp_code", None)
            request.session.pop("otp_user_id", None)
            return redirect("index")
        else:
            messages.error(request, "Invalid OTP. Please try again.")

    return render(request, "registration/login.html", {"show_otp": True, "form": LoginForm()})


def logout_view(request):
    logout(request)
    return redirect("login")


# ── Dashboard ────────────────────────────────────────────────

@login_required
def index_view(request):
    user = request.user
    rsa_pub, rsa_priv = get_rsa_keys(user)

    email = rsa_decrypt(bytes(user.email_ct), rsa_priv).decode() if user.email_ct else ""
    phone = rsa_decrypt(bytes(user.phone_ct), rsa_priv).decode() if user.phone_ct else ""

    posts = []
    for p in Post.objects.filter(user=user).order_by("-created_at"):
        try:
            title = rsa_decrypt(bytes(p.title_ct), rsa_priv).decode()
        except Exception:
            title = "[decrypt error]"
        posts.append({
            "id": p.id,
            "title": title or "Untitled",
            "created_at": p.created_at,
            "is_public": p.is_public,
        })

    return render(request, "index.html", {"email": email, "phone": phone, "posts": posts})


# ── Feed ─────────────────────────────────────────────────────

@login_required
def feed_view(request):
    items = []
    for p in Post.objects.filter(is_public=True).select_related("user").order_by("-created_at"):
        try:
            _, owner_priv = get_rsa_keys(p.user)
            title  = rsa_decrypt(bytes(p.title_ct), owner_priv).decode()
            body   = rsa_decrypt(bytes(p.body_ct),  owner_priv).decode()
            mac_ok = True
            if p.mac:
                owner_priv_raw = decrypt_with_server_key(bytes(p.user.rsa_private_key))
            mac_ok = verify_mac(owner_priv_raw,
                                    bytes(p.title_ct) + bytes(p.body_ct),
                                    bytes(p.mac))
        except Exception:
            title, body, mac_ok = "[error]", "", False

        items.append({
            "id": p.id, "author": p.user.username,
            "title": title, "body": body,
            "created_at": p.created_at, "mac_ok": mac_ok,
        })

    return render(request, "feed.html", {"items": items})


# ── Posts ─────────────────────────────────────────────────────

@login_required
def post_new_view(request):
    if request.method == "POST":
        title     = request.POST.get("title", "").strip()
        body      = request.POST.get("body", "").strip()
        is_public = request.POST.get("is_public") == "on"

        if not title or not body:
            messages.error(request, "Title and body are required.")
            return redirect("post_new")

        rsa_pub, rsa_priv = get_rsa_keys(request.user)
        title_ct = rsa_encrypt(title.encode(), rsa_pub)
        body_ct  = rsa_encrypt(body.encode(),  rsa_pub)
        rsa_priv_raw = decrypt_with_server_key(bytes(request.user.rsa_private_key))
        mac      = compute_mac(rsa_priv_raw, title_ct + body_ct)

        Post.objects.create(
            user=request.user,
            title_ct=title_ct, body_ct=body_ct,
            mac=mac, is_public=is_public,
        )
        messages.success(request, "Post created.")
        return redirect("index")

    return render(request, "post_new.html")


@login_required
def post_detail_view(request, post_id):
    p = get_object_or_404(Post, id=post_id)

    if not p.is_public and p.user_id != request.user.id:
        messages.error(request, "You do not have permission.")
        return redirect("index")

    _, owner_priv = get_rsa_keys(p.user)
    title  = rsa_decrypt(bytes(p.title_ct), owner_priv).decode()
    body   = rsa_decrypt(bytes(p.body_ct),  owner_priv).decode()
    mac_ok = True
    if p.mac:
        post_priv_raw = decrypt_with_server_key(bytes(p.user.rsa_private_key))
        mac_ok = verify_mac(post_priv_raw,
                            bytes(p.title_ct) + bytes(p.body_ct),
                            bytes(p.mac))

    return render(request, "post_detail.html", {
        "post": p, "post_id": p.id,
        "title": title, "body": body,
        "mac_ok": mac_ok, "created_at": p.created_at,
        "author": p.user.username, "is_public": p.is_public,
    })


@login_required
def post_edit_view(request, post_id):
    p = get_object_or_404(Post, id=post_id, user=request.user)
    rsa_pub, rsa_priv = get_rsa_keys(request.user)

    if request.method == "POST":
        title     = request.POST.get("title", "").strip()
        body      = request.POST.get("body", "").strip()
        is_public = request.POST.get("is_public") == "on"

        if not title or not body:
            messages.error(request, "Title and body are required.")
            return redirect("post_edit", post_id=post_id)

        p.title_ct  = rsa_encrypt(title.encode(), rsa_pub)
        p.body_ct   = rsa_encrypt(body.encode(),  rsa_pub)
        p.is_public = is_public
        rsa_priv_raw2 = decrypt_with_server_key(bytes(request.user.rsa_private_key))
        p.mac       = compute_mac(rsa_priv_raw2,
                                  bytes(p.title_ct) + bytes(p.body_ct))
        p.save()
        messages.success(request, "Post updated.")
        return redirect("post_detail", post_id=p.id)

    title = rsa_decrypt(bytes(p.title_ct), rsa_priv).decode()
    body  = rsa_decrypt(bytes(p.body_ct),  rsa_priv).decode()
    return render(request, "post_edit.html", {"post": p, "title": title, "body": body})


@login_required
def post_delete_view(request, post_id):
    p = get_object_or_404(Post, id=post_id, user=request.user)

    if request.method == "POST":
        p.delete()
        messages.success(request, "Post deleted.")
        return redirect("index")

    _, rsa_priv = get_rsa_keys(request.user)
    try:
        title = rsa_decrypt(bytes(p.title_ct), rsa_priv).decode()
    except Exception:
        title = "[decrypt error]"

    return render(request, "post_delete_confirm.html", {"post": p, "title": title})


@login_required
def post_toggle_visibility(request, post_id):
    p = get_object_or_404(Post, id=post_id, user=request.user)
    if request.method == "POST":
        p.is_public = not p.is_public
        p.save()
        messages.success(request, f"Post is now {'public' if p.is_public else 'private'}.")
    return redirect("post_detail", post_id=post_id)


# ── Profile ───────────────────────────────────────────────────

@login_required
def profile_update_view(request):
    user = request.user
    rsa_pub, rsa_priv = get_rsa_keys(user)

    if request.method == "POST":
        action = request.POST.get("action", "edit")

        # Toggle private/public
        if action == "toggle_privacy":
            user.is_private = not user.is_private
            user.save()
            status = "private" if user.is_private else "public"
            messages.success(request, f"Profile is now {status}.")
            return redirect("profile_update")

        if action != "edit":
            return redirect("profile_update")

        # Save profile edits
        new_username = request.POST.get("username", "").strip()
        email_plain  = request.POST.get("email", "").strip()
        phone_plain  = request.POST.get("phone", "").strip()

        if new_username and new_username != user.username:
            if Account.objects.filter(username=new_username).exists():
                messages.error(request, "That username is already taken.")
                email = rsa_decrypt(bytes(user.email_ct), rsa_priv).decode() if user.email_ct else ""
                phone = rsa_decrypt(bytes(user.phone_ct), rsa_priv).decode() if user.phone_ct else ""
                return render(request, "profile_update.html", {"email": email, "phone": phone, "user": user})
            user.username = new_username

        if email_plain:
            user.email_ct = rsa_encrypt(email_plain.encode(), rsa_pub)
        if phone_plain:
            user.phone_ct = rsa_encrypt(phone_plain.encode(), rsa_pub)

        user.save()
        messages.success(request, "Profile updated successfully.")
        return redirect("profile_update")

    email = rsa_decrypt(bytes(user.email_ct), rsa_priv).decode() if user.email_ct else ""
    phone = rsa_decrypt(bytes(user.phone_ct), rsa_priv).decode() if user.phone_ct else ""
    return render(request, "profile_update.html", {"email": email, "phone": phone, "user": user})


# ── Message Vault ─────────────────────────────────────────────
#
# How it works:
#   1. User goes to inbox or compose — vault check runs first
#   2. If session["vault_unlocked"] is True → show messages normally
#   3. If not unlocked:
#        - User has no vault password yet → show "Create vault password" form
#        - User has a vault password      → show "Enter vault password" form
#   4. Correct password → set session["vault_unlocked"] = True → proceed
#   5. On logout → session is cleared → vault is locked again next login

@login_required
def vault_unlock_view(request):
    user     = request.user
    has_pass = bool(user.message_password)

    if request.method == "POST":
        entered = request.POST.get("vault_password", "").strip()

        if not has_pass:
            # First time — create the vault password
            if len(entered) < 4:
                messages.error(request, "Password must be at least 4 characters.")
                return render(request, "messages_inbox.html", {"vault_locked": True, "has_vault_pass": False})

            user.message_password = make_password(entered)
            user.save()
            request.session["vault_unlocked"] = True
            messages.success(request, "Vault password created. Welcome to your messages!")
            return redirect("messages_inbox")
        else:
            # Check the vault password
            if check_password(entered, user.message_password):
                request.session["vault_unlocked"] = True
                return redirect("messages_inbox")
            else:
                messages.error(request, "Wrong vault password. Try again.")
                return render(request, "messages_inbox.html", {"vault_locked": True, "has_vault_pass": True})

    return render(request, "messages_inbox.html", {"vault_locked": True, "has_vault_pass": has_pass})


@login_required
def messages_inbox_view(request):
    # Vault check — if not unlocked redirect to unlock view
    if not request.session.get("vault_unlocked"):
        return redirect("vault_unlock")

    user = request.user
    _, ecc_priv = get_ecc_keys(user)

    inbox = []
    for m in Message.objects.filter(recipient=user).select_related("sender"):
        try:
            title  = ecc_decrypt(bytes(m.title_ct), ecc_priv).decode()
            mac_ok = True
            if m.mac:
                mac_key_raw = decrypt_with_server_key(bytes(user.ecc_private_key))
                mac_ok = verify_mac(mac_key_raw,
                                    bytes(m.title_ct) + bytes(m.body_ct),
                                    bytes(m.mac))
        except Exception:
            title, mac_ok = "[decrypt error]", False

        inbox.append({
            "id": m.id, "title": title,
            "from": "Anonymous" if m.is_anonymous or not m.sender else m.sender.username,
            "mac_ok": mac_ok, "created_at": m.created_at,
        })

    return render(request, "messages_inbox.html", {"inbox": inbox, "vault_locked": False})


@login_required
def message_new_view(request):
    if not request.session.get("vault_unlocked"):
        return redirect("vault_unlock")

    if request.method == "POST":
        to_username = request.POST.get("to", "").strip()
        title       = request.POST.get("title", "").strip()
        body        = request.POST.get("body", "").strip()
        anon        = request.POST.get("anonymous") == "on"

        if not (to_username and title and body):
            messages.error(request, "All fields required.")
            return redirect("message_new")

        try:
            recipient = Account.objects.get(username=to_username)
        except Account.DoesNotExist:
            messages.error(request, "Recipient not found.")
            return redirect("message_new")

        # Block message if recipient's profile is private
        if recipient.is_private:
            messages.error(request, f"{to_username}'s profile is private. They cannot receive messages.")
            return redirect("message_new")

        ecc_pub, _ = get_ecc_keys(recipient)
        title_ct = ecc_encrypt(title.encode(), ecc_pub)
        body_ct  = ecc_encrypt(body.encode(),  ecc_pub)
        recip_priv_raw = decrypt_with_server_key(bytes(recipient.ecc_private_key))
        mac      = compute_mac(recip_priv_raw, title_ct + body_ct)

        Message.objects.create(
            recipient=recipient,
            sender=None if anon else request.user,
            is_anonymous=anon,
            title_ct=title_ct, body_ct=body_ct, mac=mac,
        )
        messages.success(request, f"Message sent to {to_username}.")
        return redirect("messages_inbox")

    return render(request, "message_new.html")


@login_required
def message_detail_view(request, msg_id):
    if not request.session.get("vault_unlocked"):
        return redirect("vault_unlock")

    m    = get_object_or_404(Message, id=msg_id, recipient=request.user)
    user = request.user
    _, ecc_priv = get_ecc_keys(user)

    title  = ecc_decrypt(bytes(m.title_ct), ecc_priv).decode()
    body   = ecc_decrypt(bytes(m.body_ct),  ecc_priv).decode()
    mac_ok = True
    if m.mac:
        ecc_priv_raw = decrypt_with_server_key(bytes(user.ecc_private_key))
        mac_ok = verify_mac(ecc_priv_raw,
                            bytes(m.title_ct) + bytes(m.body_ct),
                            bytes(m.mac))

    sender_name = "Anonymous" if m.is_anonymous or not m.sender else m.sender.username
    return render(request, "message_detail.html", {
        "title": title, "body": body,
        "from": sender_name, "mac_ok": mac_ok,
        "created_at": m.created_at,
    })


# ── Profile Picture (Steganography) ──────────────────────────

@login_required
def upload_profile_picture_view(request):
    if request.method == "POST":
        uploaded = request.FILES.get("profile_pic")
        if not uploaded:
            messages.error(request, "Please select an image.")
            return redirect("profile_update")

        image_bytes = uploaded.read()
        watermark   = f"CipherMedia:{request.user.username}"

        try:
            # Convert to PNG first so JPG compression doesn't destroy hidden bits
            from PIL import Image as PILImage
            import io
            img = PILImage.open(io.BytesIO(image_bytes)).convert("RGB")
            png_buffer = io.BytesIO()
            img.save(png_buffer, format="PNG")
            image_bytes = png_buffer.getvalue()

            # Check if picture already has someone else's watermark
            existing = extract_message(image_bytes)
            if existing.startswith("CipherMedia:"):
                original_owner = existing.split(":")[1]
                if original_owner != request.user.username:
                    messages.error(request, 
                        f"Upload blocked! This picture belongs to '{original_owner}'. "
                        f"Watermark detected: '{existing}'")
                    return redirect("profile_update")

            watermarked = hide_message(image_bytes, watermark)
            request.user.profile_picture = watermarked
            request.user.save()
            messages.success(request, "Profile picture uploaded with hidden watermark.")
        except Exception as e:
            messages.error(request, f"Upload failed: {e}")

    return redirect("profile_update")


@login_required
def verify_profile_picture_view(request):
    user = request.user
    if not user.profile_picture:
        messages.error(request, "No profile picture uploaded yet.")
        return redirect("profile_update")

    watermark_result = None
    try:
        hidden_text = extract_message(bytes(user.profile_picture))
        if hidden_text.startswith("CipherMedia:"):
            watermark_result = hidden_text
        else:
            messages.error(request, "No valid watermark found in this image.")
    except Exception as e:
        messages.error(request, f"Verification failed: {e}")

    rsa_pub, rsa_priv = get_rsa_keys(user)
    email = rsa_decrypt(bytes(user.email_ct), rsa_priv).decode() if user.email_ct else ""
    phone = rsa_decrypt(bytes(user.phone_ct), rsa_priv).decode() if user.phone_ct else ""
    return render(request, "profile_update.html", {
        "email": email, "phone": phone,
        "user": user, "watermark_result": watermark_result
    })


@login_required
def profile_picture_view(request, user_id):
    from django.http import HttpResponse
    user = get_object_or_404(Account, id=user_id)
    if not user.profile_picture:
        return HttpResponse(status=404)
    return HttpResponse(bytes(user.profile_picture), content_type="image/png")


# ── RBAC: Admin views ─────────────────────────────────────────

from .rbac import admin_required

@admin_required
def admin_dashboard_view(request):
    all_users = Account.objects.all().order_by("-date_joined")
    all_posts = Post.objects.all().select_related("user").order_by("-created_at")

    post_list = []
    for p in all_posts:
        # Admin can only see public post titles
        # Private posts stay encrypted — admin cannot read them
        if p.is_public:
            try:
                _, priv = get_rsa_keys(p.user)
                title = rsa_decrypt(bytes(p.title_ct), priv).decode()
            except Exception:
                title = "[decrypt error]"
        else:
            title = "[Private — Encrypted]"

        post_list.append({
            "id": p.id, "author": p.user.username,
            "title": title, "is_public": p.is_public,
            "created_at": p.created_at,
        })

    return render(request, "admin_dashboard.html", {
        "all_users": all_users,
        "post_list": post_list,
    })


@admin_required
def admin_delete_user_view(request, user_id):
    target = get_object_or_404(Account, id=user_id)
    if request.method == "POST":
        target.delete()
        messages.success(request, f"User '{target.username}' deleted.")
    return redirect("admin_dashboard")


@admin_required
def admin_delete_post_view(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    if request.method == "POST":
        post.delete()
        messages.success(request, "Post deleted.")
    return redirect("admin_dashboard")


@admin_required
def admin_change_role_view(request, user_id):
    target = get_object_or_404(Account, id=user_id)
    if request.method == "POST":
        new_role = request.POST.get("role")
        if new_role in ["admin", "user"]:
            target.role = new_role
            target.save()
            messages.success(request, f"Role updated to '{new_role}'.")
    return redirect("admin_dashboard")