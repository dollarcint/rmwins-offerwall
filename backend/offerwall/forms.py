from urllib.parse import urlsplit

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from surveys.models import Survey

from .models import (
    OfferwallAdminPortalAccount,
    PlacementEventPostback,
    Publisher,
    PublisherPlacement,
    PublisherPortalAccount,
    RespondentProfile,
)
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


class AdminPortalLoginForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "username",
                "autofocus": True,
                "placeholder": "Admin username",
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
    remember_me = forms.BooleanField(required=False, initial=False, label="Keep me signed in")


class AdminPortalPasswordChangeForm(forms.Form):
    current_password = forms.CharField(
        max_length=1024,
        strip=False,
        widget=forms.PasswordInput(
            attrs={"autocomplete": "current-password", "placeholder": "Current password"}
        ),
    )
    new_password1 = forms.CharField(
        max_length=1024,
        strip=False,
        label="New password",
        widget=forms.PasswordInput(
            attrs={"autocomplete": "new-password", "placeholder": "New password"}
        ),
    )
    new_password2 = forms.CharField(
        max_length=1024,
        strip=False,
        label="Confirm new password",
        widget=forms.PasswordInput(
            attrs={"autocomplete": "new-password", "placeholder": "Confirm new password"}
        ),
    )

    def __init__(self, *args, user, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_current_password(self):
        value = self.cleaned_data["current_password"]
        if not self.user.check_password(value):
            raise ValidationError("Current password is incorrect.")
        return value

    def clean_new_password1(self):
        value = self.cleaned_data["new_password1"]
        if len(value) < 12:
            raise ValidationError("Use at least 12 characters.")
        if not any(character.isalpha() for character in value) or not any(
            character.isdigit() for character in value
        ):
            raise ValidationError("Include at least one letter and one number.")
        validate_password(value, user=self.user)
        return value

    def clean(self):
        cleaned = super().clean()
        first = cleaned.get("new_password1")
        second = cleaned.get("new_password2")
        if first and second and first != second:
            self.add_error("new_password2", "Passwords do not match.")
        if first and self.user.check_password(first):
            self.add_error("new_password1", "Choose a password you have not just used.")
        return cleaned

    def save(self):
        self.user.set_password(self.cleaned_data["new_password1"])
        self.user.save(update_fields=["password"])
        account = OfferwallAdminPortalAccount.objects.get(user=self.user)
        account.must_change_password = False
        account.last_password_change_at = timezone.now()
        account.save(
            update_fields=["must_change_password", "last_password_change_at", "updated_at"]
        )
        return account


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

    platform = forms.ChoiceField(
        choices=(("web", "Web"), ("android", "Android"), ("ios", "iOS")),
        widget=forms.RadioSelect,
    )

    class Meta:
        model = PublisherPlacement
        fields = ["platform", "website_url"]
        labels = {"website_url": "Website / project URL"}
        widgets = {
            "platform": forms.RadioSelect,
            "website_url": forms.URLInput(
                attrs={
                    "placeholder": "Enter website URL",
                    "autocomplete": "url",
                }
            ),
        }

    def __init__(self, *args, publisher=None, **kwargs):
        self.publisher = publisher
        super().__init__(*args, **kwargs)
        if not self.is_bound:
            self.fields["platform"].initial = PublisherPlacement.Platform.WEB

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
        placement.currency_name = self.publisher.currency
        placement.respondent_id_parameter = "SID"
        placement.affiliate_sub_parameter = "sid2"
        if commit:
            placement.save()
        return placement


def _clean_https_url_template(value, *, required=False):
    value = str(value or "").strip()
    if not value and not required:
        return ""
    if len(value) > 2000:
        raise ValidationError("The callback URL is too long.")
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValidationError("Use a clean HTTPS URL. Supported macros may be used in its path or query.")
    return value


def _validate_brand_image(upload, *, max_bytes):
    if not upload:
        return upload
    if upload.size > max_bytes:
        raise ValidationError(f"Image must be smaller than {max_bytes // 1024} KB.")
    header = upload.read(16)
    upload.seek(0)
    is_png = header.startswith(b"\x89PNG\r\n\x1a\n")
    is_jpeg = header.startswith(b"\xff\xd8\xff")
    is_webp = header.startswith(b"RIFF") and header[8:12] == b"WEBP"
    if not (is_png or is_jpeg or is_webp):
        raise ValidationError("Upload a PNG, JPEG or WebP image.")
    return upload


class PlacementGeneralForm(forms.ModelForm):
    class Meta:
        model = PublisherPlacement
        fields = ["traffic_type", "allowed_domains"]
        widgets = {
            "traffic_type": forms.RadioSelect,
            "allowed_domains": forms.Textarea(
                attrs={
                    "rows": 4,
                    "placeholder": "rewards.example.com\napp.example.com",
                }
            ),
        }

    def clean_allowed_domains(self):
        value = str(self.cleaned_data.get("allowed_domains") or "")
        domains = []
        for raw_value in value.splitlines():
            candidate = raw_value.strip().lower().rstrip("/")
            if not candidate:
                continue
            wildcard = candidate.startswith("*.") or candidate.startswith("https://*.")
            parse_value = candidate
            if candidate.startswith("https://*."):
                parse_value = "https://" + candidate[len("https://*.") :]
            elif candidate.startswith("*."):
                parse_value = "https://" + candidate[2:]
            elif "://" not in candidate:
                parse_value = "https://" + candidate
            parsed = urlsplit(parse_value)
            try:
                port = parsed.port
            except ValueError as exc:
                raise ValidationError(f"Invalid allowed domain: {raw_value}") from exc
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
            ):
                raise ValidationError(
                    f"Use a hostname or clean HTTPS origin for allowed domain: {raw_value}"
                )
            host = parsed.hostname.lower()
            if any(character.isspace() for character in host) or "_" in host:
                raise ValidationError(f"Invalid allowed domain: {raw_value}")
            normalized = f"{'*.' if wildcard else ''}{host}"
            if port:
                normalized = f"{normalized}:{port}"
            if normalized not in domains:
                domains.append(normalized)
        if len(domains) > 20:
            raise ValidationError("Add no more than 20 allowed domains.")
        return "\n".join(domains)


class PlacementCurrencyForm(forms.ModelForm):
    class Meta:
        model = PublisherPlacement
        fields = [
            "currency_name",
            "user_revenue_share",
            "currency_multiplier",
            "reward_rounding_precision",
        ]
        widgets = {
            "currency_name": forms.TextInput(
                attrs={"maxlength": 6, "placeholder": "e.g. Points, Coins, Gems"}
            ),
            "user_revenue_share": forms.NumberInput(attrs={"min": 0, "max": 100, "step": "0.01"}),
            "currency_multiplier": forms.NumberInput(attrs={"min": "0.000001", "step": "0.000001"}),
        }

    def clean_currency_name(self):
        value = str(self.cleaned_data.get("currency_name") or "").strip()
        if not value:
            raise ValidationError("Enter a currency name.")
        return value


class PlacementPostbackForm(forms.ModelForm):
    postback_url = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "placeholder": "https://example.com/postback?user_id={SID}&status={STATUS}",
                "autocomplete": "url",
            }
        ),
    )

    class Meta:
        model = PublisherPlacement
        fields = [
            "postback_url",
            "whitelist_postback_ip",
            "postback_email_opt_out",
        ]

    def clean_postback_url(self):
        return _clean_https_url_template(
            self.cleaned_data.get("postback_url"),
            required=False,
        )

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.postback_enabled = bool(instance.postback_url)
        if commit:
            instance.save()
        return instance

class PlacementDesignForm(forms.ModelForm):
    CONTENT_CHOICES = (
        ("offers", "Offers"),
        ("survey", "Survey"),
        ("live_survey", "Live Survey"),
    )
    active_content_types = forms.MultipleChoiceField(
        choices=CONTENT_CHOICES,
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = PublisherPlacement
        fields = ["active_content_types", "currency_icon", "header_logo"]
        widgets = {
            "currency_icon": forms.ClearableFileInput(attrs={"accept": "image/png,image/jpeg,image/webp"}),
            "header_logo": forms.ClearableFileInput(attrs={"accept": "image/png,image/jpeg,image/webp"}),
        }

    def clean_currency_icon(self):
        return _validate_brand_image(self.cleaned_data.get("currency_icon"), max_bytes=500 * 1024)

    def clean_header_logo(self):
        return _validate_brand_image(self.cleaned_data.get("header_logo"), max_bytes=2 * 1024 * 1024)


class PlacementEventPostbackForm(forms.ModelForm):
    event_type = forms.ChoiceField(
        choices=(("complete", "Completed"), ("reversal", "Reversal")),
        label="Event",
    )
    survey_id = forms.CharField(
        required=True,
        label="Offer",
        widget=forms.TextInput(attrs={"placeholder": "Search offer by name or ID"}),
    )
    callback_url = forms.CharField(
        widget=forms.TextInput(
            attrs={"placeholder": "https://example.com/postback?user_id={SID}"}
        )
    )

    class Meta:
        model = PlacementEventPostback
        fields = ["event_type", "callback_url"]

    def __init__(self, *args, placement=None, **kwargs):
        self.placement = placement
        super().__init__(*args, **kwargs)

    def clean_survey_id(self):
        value = str(self.cleaned_data.get("survey_id") or "").strip()
        if not value:
            raise ValidationError("Select an offer.")
        survey = Survey.objects.filter(local_id=value).first()
        if not survey:
            raise ValidationError("No survey exists with this internal survey ID.")
        return survey

    def clean_callback_url(self):
        return _clean_https_url_template(self.cleaned_data.get("callback_url"), required=True)

    def clean(self):
        cleaned = super().clean()
        survey = cleaned.get("survey_id")
        event_type = cleaned.get("event_type")
        if self.placement and event_type:
            duplicate = PlacementEventPostback.objects.filter(
                placement=self.placement,
                survey=survey,
                event_type=event_type,
            )
            if self.instance.pk:
                duplicate = duplicate.exclude(pk=self.instance.pk)
            if duplicate.exists():
                raise ValidationError("A postback already exists for this survey and event.")
        return cleaned


class PublisherGeneralDetailsForm(forms.Form):
    """Supplier-owned business profile fields; platform and payout controls stay admin-only."""

    company_name = forms.CharField(
        max_length=160,
        widget=forms.TextInput(attrs={"autocomplete": "organization"}),
    )
    contact_name = forms.CharField(
        max_length=160,
        widget=forms.TextInput(attrs={"autocomplete": "name"}),
    )
    job_title = forms.CharField(
        max_length=120,
        required=False,
        widget=forms.TextInput(attrs={"autocomplete": "organization-title"}),
    )
    business_email = forms.EmailField(
        max_length=254,
        label="Business email",
        widget=forms.EmailInput(attrs={"autocomplete": "email"}),
    )
    phone = forms.CharField(
        max_length=40,
        required=False,
        widget=forms.TextInput(attrs={"autocomplete": "tel"}),
    )
    website = forms.URLField(
        max_length=500,
        required=False,
        widget=forms.URLInput(
            attrs={"autocomplete": "url", "placeholder": "https://company.com"}
        ),
    )
    country = forms.CharField(
        max_length=80,
        widget=forms.TextInput(attrs={"autocomplete": "country-name"}),
    )
    state = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={"autocomplete": "address-level1"}),
    )
    city = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={"autocomplete": "address-level2"}),
    )
    postal_code = forms.CharField(
        max_length=24,
        required=False,
        widget=forms.TextInput(attrs={"autocomplete": "postal-code"}),
    )
    address_line = forms.CharField(
        max_length=255,
        required=False,
        label="Street address",
        widget=forms.TextInput(attrs={"autocomplete": "street-address"}),
    )

    def __init__(self, *args, account: PublisherPortalAccount, **kwargs):
        self.account = account
        if not args and "data" not in kwargs and "initial" not in kwargs:
            kwargs["initial"] = {
                "company_name": account.publisher.name,
                "contact_name": account.contact_name,
                "job_title": account.job_title,
                "business_email": account.business_email,
                "phone": account.phone,
                "website": account.website,
                "country": account.country,
                "state": account.state,
                "city": account.city,
                "postal_code": account.postal_code,
                "address_line": account.address_line,
            }
        super().__init__(*args, **kwargs)

    def clean_business_email(self):
        user_model = get_user_model()
        value = user_model.objects.normalize_email(
            self.cleaned_data["business_email"]
        ).lower()
        account_duplicate = PublisherPortalAccount.objects.filter(
            business_email__iexact=value
        ).exclude(pk=self.account.pk)
        user_duplicate = user_model.objects.filter(email__iexact=value).exclude(
            pk=self.account.user_id
        )
        if account_duplicate.exists() or user_duplicate.exists():
            raise ValidationError("This business email belongs to another account.")
        return value

    def clean_company_name(self):
        value = str(self.cleaned_data["company_name"] or "").strip()
        if len(value) < 2:
            raise ValidationError("Enter a valid company name.")
        return value

    def save(self):
        if not self.is_valid():
            raise ValueError("Cannot save invalid general details.")
        with transaction.atomic():
            account = (
                PublisherPortalAccount.objects.select_for_update()
                .select_related("publisher", "user")
                .get(pk=self.account.pk)
            )
            account.publisher.name = self.cleaned_data["company_name"]
            account.publisher.save(update_fields=["name", "updated_at"])

            for field in (
                "contact_name",
                "job_title",
                "business_email",
                "phone",
                "website",
                "country",
                "state",
                "city",
                "postal_code",
                "address_line",
            ):
                setattr(account, field, str(self.cleaned_data.get(field) or "").strip())
            account.save(
                update_fields=[
                    "contact_name",
                    "job_title",
                    "business_email",
                    "phone",
                    "website",
                    "country",
                    "state",
                    "city",
                    "postal_code",
                    "address_line",
                    "updated_at",
                ]
            )

            account.user.first_name = account.contact_name[:150]
            account.user.email = account.business_email
            account.user.save(update_fields=["first_name", "email"])
            self.account = account
            return account


class RespondentOnboardingForm(forms.Form):
    full_name = forms.CharField(
        max_length=160,
        label="Full name",
        widget=forms.TextInput(
            attrs={"autocomplete": "name", "placeholder": "Enter your full name"}
        ),
    )
    email = forms.EmailField(
        max_length=254,
        widget=forms.EmailInput(
            attrs={"autocomplete": "email", "placeholder": "you@example.com"}
        ),
    )
    age = forms.IntegerField(
        min_value=18,
        max_value=100,
        widget=forms.NumberInput(
            attrs={"inputmode": "numeric", "min": "18", "max": "100", "placeholder": "Age"}
        ),
    )
    gender = forms.ChoiceField(
        choices=RespondentProfile.Gender.choices,
        widget=forms.Select,
    )
    consent = forms.BooleanField(
        label="I agree that these details may be used for survey matching, verification and rewards."
    )

    def __init__(self, *args, publisher=None, profile=None, **kwargs):
        self.publisher = publisher
        self.profile = profile
        super().__init__(*args, **kwargs)

    def clean_email(self):
        from .respondent_security import normalize_respondent_email, respondent_email_hash

        email = normalize_respondent_email(self.cleaned_data["email"])
        if self.publisher:
            matches = RespondentProfile.objects.filter(
                publisher=self.publisher,
                email_hash=respondent_email_hash(email),
            )
            if self.profile:
                matches = matches.exclude(pk=self.profile.pk)
            if matches.exists():
                raise ValidationError("This email is already linked to another respondent ID.")
        return email


class RespondentVerificationForm(forms.Form):
    code = forms.CharField(
        min_length=6,
        max_length=6,
        label="Verification code",
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "pattern": "[0-9]{6}",
                "placeholder": "6-digit code",
            }
        ),
    )

    def clean_code(self):
        code = str(self.cleaned_data["code"] or "").strip()
        if not code.isdigit():
            raise ValidationError("Enter the 6-digit code from your email.")
        return code

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.placement = self.placement
        instance.survey = self.cleaned_data.get("survey_id")
        instance.event_name = dict(self.fields["event_type"].choices).get(
            instance.event_type, instance.event_type
        )
        if commit:
            instance.save()
        return instance
