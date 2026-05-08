from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password

User = get_user_model()

def check_credentials(username: str, password: str):
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return None
    if not user.is_active:
        return None
    return user if check_password(password, user.password) else None
