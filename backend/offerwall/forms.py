import re
from urllib.parse import urlsplit

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import Publisher, PublisherPlacement
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


class PublisherPlacementCreateForm(forms.ModelForm):
    """Small first-step form matching the publisher placement workflow."""

    class Meta:
        model = PublisherPlacement
        fields = ["platform", "website_url"]
        labels = {"website_url": "Website / project URL"}
        widgets = {
            "platform": forms.RadioSelect,
            "website_url": forms.URLInput(
                attrs={
                    "placeholder": "https://yourwebsite.com",
                    "autocomplete": "url",
                }
            ),
        }

    def __init__(self, *args, publisher=None, **kwargs):
        self.publisher = publisher
        super().__init__(*args, **kwargs)

    def clean_website_url(self):
        value = str(self.cleaned_data.get("website_url") or "").strip()
        if not value.lower().startswith("https://"):
            raise ValidationError("Use an HTTPS URL.")
        return value

    def save(self, commit=True):
        if not self.publisher:
            raise ValueError("A publisher is required to create a placement.")
        placement = super().save(commit=False)
        placement.publisher = self.publisher
        hostname = str(urlsplit(placement.website_url).hostname or "placement")
        hostname = hostname.lower().removeprefix("www.")
        raw_label = hostname.split(".")[0].replace("-", " ").replace("_", " ")
        label = " ".join(part.capitalize() for part in raw_label.split()) or "Placement"
        placement.website_name = label

        base_name = label
        candidate = base_name
        suffix = 2
        while PublisherPlacement.objects.filter(
            publisher=self.publisher,
            name__iexact=candidate,
        ).exists():
            candidate = f"{base_name} {suffix}"
            suffix += 1
        placement.name = candidate
        placement.currency = self.publisher.currency
        if commit:
            placement.save()
        return placement


class PublisherPlacementForm(forms.ModelForm):
    class Meta:
        model = PublisherPlacement
        fields = [
            "platform",
            "name",
            "website_name",
            "website_url",
            "allowed_domains",
            "postback_enabled",
            "postback_url",
            "currency",
            "currency_multiplier",
            "respondent_id_parameter",
            "campaign_id_parameter",
            "affiliate_sub_parameter",
        ]
        labels = {
            "postback_url": "Base postback URL",
            "allowed_domains": "Additional allowed domains",
            "respondent_id_parameter": "Respondent ID variable",
            "campaign_id_parameter": "Campaign ID variable",
            "affiliate_sub_parameter": "Affiliate sub variable",
        }
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "e.g. Main rewards wall"}),
            "website_name": forms.TextInput(attrs={"placeholder": "e.g. My Rewards App"}),
            "website_url": forms.URLInput(attrs={"placeholder": "https://example.com"}),
            "postback_url": forms.URLInput(
                attrs={"placeholder": "https://example.com/postback (optional)"}
            ),
            "allowed_domains": forms.Textarea(
                attrs={
                    "placeholder": "rewards.example.com\napp.example.com",
                    "rows": 3,
                }
            ),
            "currency": forms.TextInput(attrs={"placeholder": "USD", "maxlength": 3}),
            "currency_multiplier": forms.NumberInput(
                attrs={"step": "0.000001", "min": "0.000001"}
            ),
            "respondent_id_parameter": forms.TextInput(attrs={"placeholder": "uid"}),
            "campaign_id_parameter": forms.TextInput(attrs={"placeholder": "campaign_id"}),
            "affiliate_sub_parameter": forms.TextInput(attrs={"placeholder": "subid"}),
        }

    def __init__(self, *args, publisher=None, **kwargs):
        self.publisher = publisher
        super().__init__(*args, **kwargs)

    def clean_currency(self):
        currency = str(self.cleaned_data.get("currency") or "").strip().upper()
        if not re.fullmatch(r"[A-Z]{3}", currency):
            raise ValidationError("Enter a three-letter currency code such as USD.")
        return currency

    def clean_website_url(self):
        return self._secure_url("website_url", required=True)

    def clean_postback_url(self):
        return self._secure_url("postback_url", required=False)

    def clean_allowed_domains(self):
        raw_value = str(self.cleaned_data.get("allowed_domains") or "")
        domains = []
        for raw_domain in re.split(r"[,\s]+", raw_value):
            value = raw_domain.strip().lower()
            if not value:
                continue
            value = value.removeprefix("*.")
            parsed = urlsplit(value if "://" in value else f"//{value}")
            try:
                hostname = parsed.hostname
                port = parsed.port
            except ValueError as exc:
                raise ValidationError(
                    "Enter domains only, such as rewards.example.com."
                ) from exc
            if (
                parsed.scheme not in {"", "http", "https"}
                or not hostname
                or parsed.username
                or parsed.password
                or port
                or (parsed.path and parsed.path != "/")
                or parsed.query
                or parsed.fragment
            ):
                raise ValidationError("Enter domains only, such as rewards.example.com.")
            domain = hostname.lower().rstrip(".")
            if domain not in domains:
                domains.append(domain)
        return "\n".join(domains)

    def _secure_url(self, field_name, *, required):
        value = str(self.cleaned_data.get(field_name) or "").strip()
        if not value and not required:
            return ""
        if not value.lower().startswith("https://"):
            raise ValidationError("Use an HTTPS URL.")
        return value

    def clean(self):
        cleaned = super().clean()
        parameter_fields = (
            "respondent_id_parameter",
            "campaign_id_parameter",
            "affiliate_sub_parameter",
        )
        values = [str(cleaned.get(field) or "").casefold() for field in parameter_fields]
        if all(values) and len(set(values)) != len(values):
            raise ValidationError("Each variable mapping must use a different parameter name.")
        if cleaned.get("postback_enabled") and not cleaned.get("postback_url"):
            self.add_error("postback_url", "Enter a postback URL before enabling callbacks.")
        if self.publisher and cleaned.get("name"):
            duplicate = PublisherPlacement.objects.filter(
                publisher=self.publisher,
                name__iexact=str(cleaned["name"]).strip(),
            )
            if self.instance.pk:
                duplicate = duplicate.exclude(pk=self.instance.pk)
            if duplicate.exists():
                self.add_error("name", "You already have a placement with this name.")
        return cleaned
