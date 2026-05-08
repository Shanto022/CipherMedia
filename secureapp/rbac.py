from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("login")
        if request.user.role != "admin":
            messages.error(request, "Admin access required.")
            return redirect("index")
        return view_func(request, *args, **kwargs)
    return wrapper


def is_admin(user):
    return user.is_authenticated and user.role == "admin"