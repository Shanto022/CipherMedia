from django.contrib import messages
from django.contrib.auth import get_user_model, logout
from django.shortcuts import redirect, render

from .crypto import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    serialize_public_key,
    deserialize_public_key,
    serialize_private_key,
    deserialize_private_key,
    generate_ecc_keypair,
    serialize_ecc_public_key,
    serialize_ecc_private_key,
)

from .forms import LoginForm, RegisterForm
from .auth_utils import check_credentials
from .server_keys import encrypt_with_server_key, decrypt_with_server_key

Account = get_user_model()

_key_cache = {}

def get_rsa_keys(user):
    cache_key = f"rsa_{user.id}"

    if cache_key not in _key_cache:
        pub = deserialize_public_key(bytes(user.rsa_public_key))
        priv_raw = decrypt_with_server_key(bytes(user.rsa_private_key))
        priv = deserialize_private_key(priv_raw)
        _key_cache[cache_key] = (pub, priv)

    return _key_cache[cache_key]


def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)

        if form.is_valid():
            username = form.cleaned_data["username"].strip()
            password = form.cleaned_data["password1"]
            email_plain = form.cleaned_data["email"].strip()
            phone_plain = form.cleaned_data["phone"].strip()

            user = Account.objects.create_user(
                username=username,
                password=password
            )

            try:
                rsa_pub, rsa_priv = generate_rsa_keypair(bits=1024)
                user.rsa_public_key = serialize_public_key(rsa_pub)
                user.rsa_private_key = encrypt_with_server_key(
                    serialize_private_key(rsa_priv)
                )

                ecc_pub, ecc_priv = generate_ecc_keypair()
                user.ecc_public_key = serialize_ecc_public_key(ecc_pub)
                user.ecc_private_key = encrypt_with_server_key(
                    serialize_ecc_private_key(ecc_priv)
                )

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
                user_email = rsa_decrypt(
                    bytes(user.email_ct),
                    rsa_priv
                ).decode()

                from .views_messages import generate_otp, send_otp_email

                otp = generate_otp()

                try:
                    send_otp_email(user_email, otp)
                except Exception:
                    messages.error(
                        request,
                        "Could not send OTP email. Check email settings."
                    )
                    return redirect("login")

                request.session["otp_code"] = otp
                request.session["otp_user_id"] = user.id

                messages.success(request, f"OTP sent to {user_email}")
                return redirect("otp_verify")

            messages.error(request, "Invalid username or password.")

    else:
        form = LoginForm()

    return render(request, "registration/login.html", {"form": form})


def logout_view(request):
    logout(request)
    return redirect("login")