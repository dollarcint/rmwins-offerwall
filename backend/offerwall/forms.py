from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import Publisher
from .security import generate_signing_secret


class PublisherAdminForm(forms.ModelForm):
    rotate_signing_secret = forms.BooleanField(
        required=False,
        help_text="Generate a new signing secret. The plaintext value is shown once after saving.",
    )
    rotate_api_key = forms.BooleanField(
        required=False,
        help_text="Generate a new inventory API key. The plaintext value is shown once after saving.",
    )

    class Meta:
        model = Publisher
        fields = "__all__"

    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.cleaned_data.get("rotate_signing_secret"):
            instance.set_signing_secret(generate_signing_secret())
        if self.cleaned_data.get("rotate_api_key"):
            instance.rotate_api_key()
        if commit:
            instance.save()
            self.save_m2m()
        return instance


class SupplierLoginForm(forms.Form):
    identity = forms.CharField(
        max_length=254,
        label="Username or business email",
        widget=forms.TextInput(
            attrs={
                "autocomplete": "username",
                "autofocus": True,
                "placeholder": "Username or business email",
            }
        ),
    )
    password = forms.CharField(
        max_length=1024,
        strip=False,
        widget=forms.PasswordInput(
            attrs={"autocomplete": "current-password", "placeholder": "Password"}
        ),
    )
    remember_me = forms.BooleanField(required=False, initial=True, label="Keep me signed in")


class SupplierSignupForm(forms.Form):
    company_name = forms.CharField(
        max_length=160,
        widget=forms.TextInput(attrs={"autocomplete": "organization", "placeholder": "Company name"}),
    )
    contact_name = forms.CharField(
        max_length=160,
        widget=forms.TextInput(attrs={"autocomplete": "name", "placeholder": "Contact person"}),
    )
    business_email = forms.EmailField(
        max_length=254,
        label="Business email",
        widget=forms.EmailInput(attrs={"autocomplete": "email", "placeholder": "name@company.com"}),
    )
    phone = forms.CharField(
        max_length=40,
        widget=forms.TextInput(attrs={"autocomplete": "tel", "placeholder": "+1 555 000 0000"}),
    )
    website = forms.URLField(
        max_length=500,
        required=False,
        widget=forms.URLInput(attrs={"autocomplete": "url", "placeholder": "https://company.com"}),
    )
    country = forms.CharField(
        max_length=80,
        widget=forms.TextInput(attrs={"autocomplete": "country-name", "placeholder": "Country"}),
    )
    username = forms.CharField(
        max_length=150,
        min_length=3,
        widget=forms.TextInput(attrs={"autocomplete": "username", "placeholder": "Choose a username"}),
    )
    password1 = forms.CharField(
        max_length=1024,
        strip=False,
        label="Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "placeholder": "Create a strong password"}),
    )
    password2 = forms.CharField(
        max_length=1024,
        strip=False,
        label="Confirm password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "placeholder": "Repeat your password"}),
    )
    accept_terms = forms.BooleanField(
        label="I confirm that I represent this company and accept the platform terms."
    )

    def clean_username(self):
        user_model = get_user_model()
        username = user_model.normalize_username(self.cleaned_data["username"]).strip()
        if user_model.objects.filter(username__iexact=username).exists():
            raise ValidationError("This username is already registered.")
        return username

    def clean_business_email(self):
        email = get_user_model().objects.normalize_email(self.cleaned_data["business_email"]).lower()
        if get_user_model().objects.filter(email__iexact=email).exists():
            raise ValidationError("This business email is already registered.")
        return email

    def clean(self):
        cleaned = super().clean()
        password = cleaned.get("password1")
        confirmation = cleaned.get("password2")
        if password and confirmation and password != confirmation:
            self.add_error("password2", "Passwords do not match.")
            return cleaned
        if password:
            candidate = get_user_model()(
                username=cleaned.get("username", ""),
                email=cleaned.get("business_email", ""),
            )
            try:
                validate_password(password, user=candidate)
            except ValidationError as exc:
                self.add_error("password1", exc)
        return cleaned
