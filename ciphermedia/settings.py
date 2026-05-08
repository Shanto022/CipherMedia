from pathlib import Path
import environ
import os

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(DEBUG=(bool, False))
environ.Env.read_env(os.path.join(BASE_DIR, ".env")) if os.path.exists(os.path.join(BASE_DIR, ".env")) else None

SECRET_KEY = env("SECRET_KEY", default="dev-insecure")
DEBUG      = env.bool("DEBUG", default=True)

ALLOWED_HOSTS = ["127.0.0.1", "localhost", "[::1]"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "secureapp",
    "keymgmt",
    "argon2",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "ciphermedia.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "secureapp" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "ciphermedia.wsgi.application"

DATABASES = {
    "default": env.db(default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}")
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

LANGUAGE_CODE = "en-us"
TIME_ZONE     = "Asia/Dhaka"
USE_I18N      = True
USE_TZ        = True

STATIC_URL         = "static/"
STATICFILES_DIRS   = [BASE_DIR / "secureapp" / "static"]
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_USER_MODEL      = "secureapp.Account"
LOGIN_URL            = "/"
LOGIN_REDIRECT_URL   = "/home/"
LOGOUT_REDIRECT_URL  = "/"

APP_KEK_BASE64 = env("APP_KEK_BASE64", default=None)
if not APP_KEK_BASE64:
    raise RuntimeError("APP_KEK_BASE64 not set in .env")

KEYMGMT_ACTIVE_KEK_ID = int(os.getenv("KEYMGMT_ACTIVE_KEK_ID", "1"))

SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE    = False
SECURE_SSL_REDIRECT   = False

# ── Server RSA keys (for encrypting user private keys) ───────
SERVER_RSA_PUBLIC_KEY  = env("SERVER_RSA_PUBLIC_KEY",  default="")
SERVER_RSA_PRIVATE_KEY = env("SERVER_RSA_PRIVATE_KEY", default="")

# ── Email (Gmail SMTP) ────────────────────────────────────────
EMAIL_BACKEND       = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST          = "smtp.gmail.com"
EMAIL_PORT          = 587
EMAIL_USE_TLS       = True
EMAIL_HOST_USER     = env("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", default="")
DEFAULT_FROM_EMAIL  = env("EMAIL_HOST_USER", default="")

# ── Secure Session Management ─────────────────────────────────
SESSION_COOKIE_HTTPONLY      = True      # JavaScript cannot access session cookie
SESSION_COOKIE_SAMESITE      = "Lax"    # Prevents cross-site session hijacking
SESSION_COOKIE_AGE           = 60 * 30  # Session expires after 30 minutes
SESSION_EXPIRE_AT_BROWSER_CLOSE = True  # Session ends when browser closes
SESSION_SAVE_EVERY_REQUEST   = True     # Refreshes session timer on every request