from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.http import HttpResponse

from .crypto import rsa_encrypt, rsa_decrypt
from .mac import compute_mac, verify_mac
from .models import Post
from .steganography import hide_message, extract_message
from .server_keys import decrypt_with_server_key
from .rbac import admin_required
from .views_auth import get_rsa_keys

Account = get_user_model()


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


@login_required
def feed_view(request):
    items = []

    for p in Post.objects.filter(is_public=True).select_related("user").order_by("-created_at"):
        try:
            _, owner_priv = get_rsa_keys(p.user)
            title = rsa_decrypt(bytes(p.title_ct), owner_priv).decode()
            body = rsa_decrypt(bytes(p.body_ct), owner_priv).decode()

            mac_ok = True
            if p.mac:
                owner_priv_raw = decrypt_with_server_key(bytes(p.user.rsa_private_key))
                mac_ok = verify_mac(
                    owner_priv_raw,
                    bytes(p.title_ct) + bytes(p.body_ct),
                    bytes(p.mac)
                )

        except Exception:
            title, body, mac_ok = "[error]", "", False

        items.append({
            "id": p.id,
            "author": p.user.username,
            "title": title,
            "body": body,
            "created_at": p.created_at,
            "mac_ok": mac_ok,
        })

    return render(request, "feed.html", {"items": items})


@login_required
def post_new_view(request):
    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        body = request.POST.get("body", "").strip()
        is_public = request.POST.get("is_public") == "on"

        if not title or not body:
            messages.error(request, "Title and body are required.")
            return redirect("post_new")

        rsa_pub, rsa_priv = get_rsa_keys(request.user)

        title_ct = rsa_encrypt(title.encode(), rsa_pub)
        body_ct = rsa_encrypt(body.encode(), rsa_pub)

        rsa_priv_raw = decrypt_with_server_key(bytes(request.user.rsa_private_key))
        mac = compute_mac(rsa_priv_raw, title_ct + body_ct)

        Post.objects.create(
            user=request.user,
            title_ct=title_ct,
            body_ct=body_ct,
            mac=mac,
            is_public=is_public,
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

    title = rsa_decrypt(bytes(p.title_ct), owner_priv).decode()
    body = rsa_decrypt(bytes(p.body_ct), owner_priv).decode()

    mac_ok = True
    if p.mac:
        post_priv_raw = decrypt_with_server_key(bytes(p.user.rsa_private_key))
        mac_ok = verify_mac(
            post_priv_raw,
            bytes(p.title_ct) + bytes(p.body_ct),
            bytes(p.mac)
        )

    return render(request, "post_detail.html", {
        "post": p,
        "post_id": p.id,
        "title": title,
        "body": body,
        "mac_ok": mac_ok,
        "created_at": p.created_at,
        "author": p.user.username,
        "is_public": p.is_public,
    })


@login_required
def post_edit_view(request, post_id):
    p = get_object_or_404(Post, id=post_id, user=request.user)
    rsa_pub, rsa_priv = get_rsa_keys(request.user)

    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        body = request.POST.get("body", "").strip()
        is_public = request.POST.get("is_public") == "on"

        if not title or not body:
            messages.error(request, "Title and body are required.")
            return redirect("post_edit", post_id=post_id)

        p.title_ct = rsa_encrypt(title.encode(), rsa_pub)
        p.body_ct = rsa_encrypt(body.encode(), rsa_pub)
        p.is_public = is_public

        rsa_priv_raw2 = decrypt_with_server_key(bytes(request.user.rsa_private_key))
        p.mac = compute_mac(rsa_priv_raw2, bytes(p.title_ct) + bytes(p.body_ct))
        p.save()

        messages.success(request, "Post updated.")
        return redirect("post_detail", post_id=p.id)

    title = rsa_decrypt(bytes(p.title_ct), rsa_priv).decode()
    body = rsa_decrypt(bytes(p.body_ct), rsa_priv).decode()

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


@login_required
def profile_update_view(request):
    user = request.user
    rsa_pub, rsa_priv = get_rsa_keys(user)

    if request.method == "POST":
        action = request.POST.get("action", "edit")

        if action == "toggle_privacy":
            user.is_private = not user.is_private
            user.save()
            status = "private" if user.is_private else "public"
            messages.success(request, f"Profile is now {status}.")
            return redirect("profile_update")

        if action != "edit":
            return redirect("profile_update")

        new_username = request.POST.get("username", "").strip()
        email_plain = request.POST.get("email", "").strip()
        phone_plain = request.POST.get("phone", "").strip()

        if new_username and new_username != user.username:
            if Account.objects.filter(username=new_username).exists():
                messages.error(request, "That username is already taken.")
                email = rsa_decrypt(bytes(user.email_ct), rsa_priv).decode() if user.email_ct else ""
                phone = rsa_decrypt(bytes(user.phone_ct), rsa_priv).decode() if user.phone_ct else ""
                return render(request, "profile_update.html", {
                    "email": email,
                    "phone": phone,
                    "user": user
                })

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

    return render(request, "profile_update.html", {
        "email": email,
        "phone": phone,
        "user": user
    })


@login_required
def upload_profile_picture_view(request):
    if request.method == "POST":
        uploaded = request.FILES.get("profile_pic")

        if not uploaded:
            messages.error(request, "Please select an image.")
            return redirect("profile_update")

        image_bytes = uploaded.read()
        watermark = f"CipherMedia:{request.user.username}"

        try:
            from PIL import Image as PILImage
            import io

            img = PILImage.open(io.BytesIO(image_bytes)).convert("RGB")
            png_buffer = io.BytesIO()
            img.save(png_buffer, format="PNG")
            image_bytes = png_buffer.getvalue()

            existing = extract_message(image_bytes)

            if existing.startswith("CipherMedia:"):
                original_owner = existing.split(":")[1]

                if original_owner != request.user.username:
                    messages.error(
                        request,
                        f"Upload blocked! This picture belongs to '{original_owner}'. "
                        f"Watermark detected: '{existing}'"
                    )
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
        "email": email,
        "phone": phone,
        "user": user,
        "watermark_result": watermark_result
    })


@login_required
def profile_picture_view(request, user_id):
    user = get_object_or_404(Account, id=user_id)

    if not user.profile_picture:
        return HttpResponse(status=404)

    return HttpResponse(bytes(user.profile_picture), content_type="image/png")


@admin_required
def admin_dashboard_view(request):
    all_users = Account.objects.all().order_by("-date_joined")
    all_posts = Post.objects.all().select_related("user").order_by("-created_at")

    post_list = []

    for p in all_posts:
        if p.is_public:
            try:
                _, priv = get_rsa_keys(p.user)
                title = rsa_decrypt(bytes(p.title_ct), priv).decode()
            except Exception:
                title = "[decrypt error]"
        else:
            title = "[Private — Encrypted]"

        post_list.append({
            "id": p.id,
            "author": p.user.username,
            "title": title,
            "is_public": p.is_public,
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