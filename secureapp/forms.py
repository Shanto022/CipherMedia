# secureapp/forms.py
from django import forms

class RegisterForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            "class": "input",
            "placeholder": "choose_a_username",
            "autocapitalize": "none",
            "autocomplete": "username",
            "spellcheck": "false",
            "autofocus": "autofocus",
        }),
        label="Username",
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            "class": "input",
            "placeholder": "••••••••",
            "autocomplete": "new-password",
        }),
        label="Password",
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            "class": "input",
            "placeholder": "repeat password",
            "autocomplete": "new-password",
        }),
        label="Confirm Password",
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            "class": "input",
            "placeholder": "you@example.com",
            "autocomplete": "email",
        }),
        label="Email",
    )
    phone = forms.CharField(
        max_length=20,
        widget=forms.TextInput(attrs={
            "class": "input",
            "placeholder": "01XXXXXXXXX",
            "autocomplete": "tel-national",
        }),
        label="Phone",
    )

    def clean(self):
        data = super().clean()
        p1, p2 = data.get("password1"), data.get("password2")
        if p1 and p2 and p1 != p2:
            self.add_error("password2", "Passwords do not match.")
        return data


class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            "class": "input",
            "placeholder": "username",
            "autocapitalize": "none",
            "autocomplete": "username",
            "spellcheck": "false",
            "autofocus": "autofocus",
        }),
        label="Username",
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            "class": "input",
            "placeholder": "••••••••",
            "autocomplete": "current-password",
        }),
        label="Password",
    )
