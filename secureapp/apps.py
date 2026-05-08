from django.apps import AppConfig

class SecureappConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "secureapp"

class KeymgmtConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "keymgmt"
