"""Offerwall publishers, sessions, click attribution and immutable rewards."""

import uuid
from decimal import Decimal

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models, transaction
from django.utils import timezone

from .security import (
    encrypt_api_key,
    encrypt_signing_secret,
    generate_api_key,
    generate_signing_secret,
)


PERCENTAGE_VALIDATORS = [MinValueValidator(Decimal("0.00")), MaxValueValidator(Decimal("100.00"))]


def default_placement_content_types():
    return ["survey", "live_survey"]


def _placement_asset_name(instance, filename, kind):
    extension = str(filename or "").lower().rsplit(".", 1)[-1]
    extension = extension if extension in {"png", "jpg", "jpeg", "webp"} else "bin"
    return f"offerwall/placements/{instance.public_id.hex}/{kind}.{extension}"


def placement_currency_icon_path(instance, filename):
    return _placement_asset_name(instance, filename, "currency-icon")


def placement_header_logo_path(instance, filename):
    return _placement_asset_name(instance, filename, "header-logo")


class PublisherNumberSequence(models.Model):
    """Locked counter for gap-independent public publisher numbering."""

    key = models.CharField(max_length=32, primary_key=True, default="publisher", editable=False)
    next_value = models.PositiveBigIntegerField(default=1, editable=False)


class Publisher(models.Model):
    """One external publisher/application embedding the RM Wins offerwall."""

    name = models.CharField(max_length=160)
    slug = models.SlugField(
        max_length=64,
        unique=True,
        validators=[RegexValidator(r"^[a-z][a-z0-9-]{2,63}$")],
        help_text="Stable public publisher code used in signed wall URLs.",
    )
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    publisher_number = models.PositiveBigIntegerField(unique=True, editable=False)
    service_user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        editable=False,
        on_delete=models.SET_NULL,
        related_name="offerwall_publisher",
    )
    callback_url = models.URLField(
        max_length=2000,
        blank=True,
        help_text="HTTPS server-to-server endpoint receiving signed outcomes.",
    )
    postback_enabled = models.BooleanField(default=False)
    payout_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal("70.00"),
        validators=PERCENTAGE_VALIDATORS,
        help_text="Percentage of source CPI credited to this publisher.",
    )
    currency = models.CharField(max_length=3, default="USD")
    is_active = models.BooleanField(default=True, db_index=True)
    encrypted_signing_secret = models.TextField(blank=True, editable=False)
    signing_secret_last_four = models.CharField(max_length=4, blank=True, editable=False)
    signing_secret_changed_at = models.DateTimeField(null=True, blank=True, editable=False)
    api_key_hash = models.CharField(max_length=64, blank=True, unique=True, null=True, editable=False)
    encrypted_api_key = models.TextField(blank=True, editable=False)
    api_key_prefix = models.CharField(max_length=16, blank=True, editable=False)
    api_key_last_four = models.CharField(max_length=4, blank=True, editable=False)
    api_key_changed_at = models.DateTimeField(null=True, blank=True, editable=False)
    api_key_last_used_at = models.DateTimeField(null=True, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name", "slug"]

    def __str__(self):
        return f"{self.name} ({self.slug})"

    @property
    def publisher_code(self):
        """Sequential integration ID backed by a dedicated database sequence."""
        return str(self.publisher_number) if self.publisher_number is not None else ""

    @property
    def masked_api_key(self):
        return (
            f"{self.api_key_prefix}••••{self.api_key_last_four}"
            if self.api_key_prefix
            else "Not generated"
        )

    @property
    def masked_signing_secret(self):
        return f"••••{self.signing_secret_last_four}" if self.signing_secret_last_four else "Not generated"

    def set_signing_secret(self, raw_secret: str):
        raw_secret = str(raw_secret or "").strip()
        if len(raw_secret) < 32:
            raise ValueError("Offerwall signing secrets must contain at least 32 characters.")
        self.encrypted_signing_secret = encrypt_signing_secret(raw_secret)
        self.signing_secret_last_four = raw_secret[-4:]
        self.signing_secret_changed_at = timezone.now()
        self._generated_signing_secret = raw_secret

    def rotate_api_key(self):
        raw_key, prefix, last_four, key_hash = generate_api_key()
        self.api_key_hash = key_hash
        self.encrypted_api_key = encrypt_api_key(raw_key)
        self.api_key_prefix = prefix
        self.api_key_last_four = last_four
        self.api_key_changed_at = timezone.now()
        self.api_key_last_used_at = None
        self._generated_api_key = raw_key
        return raw_key

    def save(self, *args, **kwargs):
        self.slug = str(self.slug or "").strip().lower()
        self.currency = str(self.currency or "USD").strip().upper()
        if not self.encrypted_signing_secret:
            self.set_signing_secret(generate_signing_secret())
        if not self.api_key_hash:
            self.rotate_api_key()
        if self._state.adding and self.publisher_number is None:
            with transaction.atomic():
                sequence, _ = PublisherNumberSequence.objects.select_for_update().get_or_create(
                    key="publisher",
                    defaults={"next_value": 1},
                )
                self.publisher_number = sequence.next_value
                sequence.next_value += 1
                sequence.save(update_fields=["next_value"])
                return super().save(*args, **kwargs)
        super().save(*args, **kwargs)


class PublisherPortalAccount(models.Model):
    """Supplier-owned login awaiting an explicit RM Wins approval."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending review"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="offerwall_portal_account",
    )
    publisher = models.OneToOneField(
        Publisher,
        on_delete=models.PROTECT,
        related_name="portal_account",
    )
    contact_name = models.CharField(max_length=160)
    business_email = models.EmailField(max_length=254, unique=True)
    phone = models.CharField(max_length=40, blank=True)
    website = models.URLField(max_length=500, blank=True)
    country = models.CharField(max_length=80)
    job_title = models.CharField(max_length=120, blank=True)
    address_line = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=24, blank=True)
    status = models.CharField(
        max_length=12,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    admin_note = models.CharField(max_length=500, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reviewed_offerwall_registrations",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Supplier registration"
        verbose_name_plural = "Supplier registrations"

    def __str__(self):
        return f"{self.publisher.name} · {self.user.username} · {self.status}"


class OfferOverride(models.Model):
    """Publisher-specific exclusion, reward or presentation override for a survey."""

    publisher = models.ForeignKey(Publisher, on_delete=models.CASCADE, related_name="offer_overrides")
    survey = models.ForeignKey("surveys.Survey", on_delete=models.CASCADE, related_name="offerwall_overrides")
    is_excluded = models.BooleanField(default=False, db_index=True)
    title_override = models.CharField(max_length=500, blank=True)
    payout_percent_override = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        validators=PERCENTAGE_VALIDATORS,
    )
    featured = models.BooleanField(default=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["publisher", "survey"]
        constraints = [
            models.UniqueConstraint(fields=["publisher", "survey"], name="unique_publisher_offer_override")
        ]

    def __str__(self):
        return f"{self.publisher.slug} · {self.survey.local_id}"


class PublisherPlacement(models.Model):
    """Supplier-managed website placement used to embed the offerwall."""

    class Platform(models.TextChoices):
        WEB = "web", "Website"
        ANDROID = "android", "Android"
        IOS = "ios", "iOS"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        PAUSED = "paused", "Paused"
        ARCHIVED = "archived", "Archived"

    class TrafficType(models.TextChoices):
        INCENT = "incent", "Rewarded"
        NON_INCENT = "non_incent", "Non-rewarded"
        BOTH = "both", "All sources"

    class RewardPrecision(models.IntegerChoices):
        ONE = 1, "1 decimal place"
        TWO = 2, "2 decimal places"
        THREE = 3, "3 decimal places"
        FOUR = 4, "4 decimal places"

    PARAMETER_VALIDATOR = RegexValidator(
        r"^[A-Za-z][A-Za-z0-9_]{0,31}$",
        "Use 1–32 letters, numbers or underscores and start with a letter.",
    )

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    publisher = models.ForeignKey(
        Publisher,
        on_delete=models.CASCADE,
        related_name="placements",
    )
    platform = models.CharField(
        max_length=12,
        choices=Platform.choices,
        default=Platform.WEB,
    )
    name = models.CharField(max_length=120)
    website_name = models.CharField(max_length=160)
    website_url = models.URLField(max_length=500)
    allowed_domains = models.TextField(
        blank=True,
        help_text="Optional additional domains, one per line. The website domain is always allowed.",
    )
    traffic_type = models.CharField(
        max_length=12,
        choices=TrafficType.choices,
        default=TrafficType.INCENT,
    )
    postback_url = models.CharField(
        max_length=2000,
        blank=True,
        help_text="Optional placement-specific HTTPS outcome endpoint with supported macros.",
    )
    postback_enabled = models.BooleanField(default=False)
    postback_email_opt_out = models.BooleanField(default=False)
    whitelist_postback_ip = models.BooleanField(default=True)
    encrypted_postback_secret = models.TextField(blank=True, editable=False)
    postback_secret_last_four = models.CharField(max_length=4, blank=True, editable=False)
    postback_secret_changed_at = models.DateTimeField(null=True, blank=True, editable=False)
    currency = models.CharField(max_length=3, default="USD")
    currency_name = models.CharField(max_length=6, default="Points")
    user_revenue_share = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=Decimal("100.00"),
        validators=PERCENTAGE_VALIDATORS,
    )
    currency_multiplier = models.DecimalField(
        max_digits=12,
        decimal_places=6,
        default=Decimal("1.000000"),
        validators=[
            MinValueValidator(Decimal("0.000001")),
            MaxValueValidator(Decimal("100000.000000")),
        ],
    )
    reward_rounding_precision = models.PositiveSmallIntegerField(
        choices=RewardPrecision.choices,
        default=RewardPrecision.TWO,
    )
    active_content_types = models.JSONField(default=default_placement_content_types)
    currency_icon = models.FileField(
        upload_to=placement_currency_icon_path,
        blank=True,
    )
    header_logo = models.FileField(
        upload_to=placement_header_logo_path,
        blank=True,
    )
    respondent_id_parameter = models.CharField(
        max_length=32,
        default="uid",
        validators=[PARAMETER_VALIDATOR],
    )
    campaign_id_parameter = models.CharField(
        max_length=32,
        default="campaign_id",
        validators=[PARAMETER_VALIDATOR],
    )
    affiliate_sub_parameter = models.CharField(
        max_length=32,
        default="subid",
        validators=[PARAMETER_VALIDATOR],
    )
    status = models.CharField(
        max_length=12,
        choices=Status.choices,
        default=Status.ACTIVE,
        db_index=True,
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["publisher", "name"],
                name="unique_publisher_placement_name",
            )
        ]
        indexes = [
            models.Index(
                fields=["publisher", "status", "-created_at"],
                name="placement_active_idx",
            )
        ]

    @property
    def masked_postback_secret(self):
        return (
            f"••••{self.postback_secret_last_four}"
            if self.postback_secret_last_four
            else "Not generated"
        )

    @property
    def is_active(self):
        return self.status == self.Status.ACTIVE

    @property
    def app_id(self):
        """Stable RM Wins placement identifier shown to the supplier."""
        return f"RMW_APP_{self.public_id.hex.upper()}"

    @property
    def allowed_domain_list(self):
        return [item for item in str(self.allowed_domains or "").splitlines() if item]

    def display_reward(self, payout):
        if payout is None:
            return None
        share = self.user_revenue_share / Decimal("100")
        scaled = Decimal(payout) * self.currency_multiplier * share
        quantum = Decimal("1").scaleb(-int(self.reward_rounding_precision))
        return scaled.quantize(quantum)

    def set_postback_secret(self, raw_secret: str):
        raw_secret = str(raw_secret or "").strip()
        if len(raw_secret) < 32:
            raise ValueError("Placement postback secrets must contain at least 32 characters.")
        self.encrypted_postback_secret = encrypt_signing_secret(raw_secret)
        self.postback_secret_last_four = raw_secret[-4:]
        self.postback_secret_changed_at = timezone.now()
        self._generated_postback_secret = raw_secret

    def save(self, *args, **kwargs):
        is_new = self._state.adding
        self.name = str(self.name or "").strip()
        self.website_name = str(self.website_name or "").strip()
        self.currency = str(self.currency or "USD").strip().upper()
        if is_new and self.currency_name == "Points" and self.currency != "USD":
            self.currency_name = self.currency
        self.currency_name = str(self.currency_name or "Points").strip()[:6]
        self.active_content_types = list(
            dict.fromkeys(
                item
                for item in (self.active_content_types or [])
                if item in {"offers", "survey", "live_survey"}
            )
        )
        if not self.encrypted_postback_secret:
            self.set_postback_secret(generate_signing_secret())
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.publisher.slug} · {self.name}"


class PlacementEventPostback(models.Model):
    """Optional offer/outcome-specific callback overriding a placement global URL."""

    class EventType(models.TextChoices):
        COMPLETE = "complete", "Completed"
        TERMINATE = "terminate", "Terminated"
        OVER_QUOTA = "over_quota", "Over quota"
        QUALITY_TERMINATE = "quality_terminate", "Quality terminated"
        REVERSAL = "reversal", "Reversal"

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    placement = models.ForeignKey(
        PublisherPlacement,
        on_delete=models.CASCADE,
        related_name="event_postbacks",
    )
    survey = models.ForeignKey(
        "surveys.Survey",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="offerwall_event_postbacks",
    )
    event_type = models.CharField(max_length=24, choices=EventType.choices)
    event_name = models.CharField(max_length=120, blank=True)
    callback_url = models.CharField(max_length=2000)
    is_active = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["placement", "event_type", "is_active"],
                name="placement_event_postback_idx",
            )
        ]

    def __str__(self):
        target = self.survey.local_id if self.survey_id else "all offers"
        return f"{self.placement.name} · {target} · {self.event_type}"


class RespondentProfile(models.Model):
    """Persistent, supplier-scoped identity collected before iframe inventory access."""

    class Gender(models.TextChoices):
        FEMALE = "female", "Female"
        MALE = "male", "Male"
        NON_BINARY = "non_binary", "Non-binary"
        OTHER = "other", "Other"
        PREFER_NOT_TO_SAY = "prefer_not_to_say", "Prefer not to say"

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    publisher = models.ForeignKey(
        Publisher,
        on_delete=models.PROTECT,
        related_name="respondents",
    )
    external_user_id = models.CharField(max_length=160)
    encrypted_name = models.TextField(editable=False)
    encrypted_email = models.TextField(editable=False)
    email_hash = models.CharField(max_length=64, editable=False)
    age = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(18), MaxValueValidator(100)]
    )
    gender = models.CharField(max_length=24, choices=Gender.choices)
    first_placement = models.ForeignKey(
        PublisherPlacement,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="first_seen_respondents",
    )
    last_placement = models.ForeignKey(
        PublisherPlacement,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="last_seen_respondents",
    )
    is_email_verified = models.BooleanField(default=False, db_index=True)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    verification_code_hash = models.CharField(max_length=64, blank=True, editable=False)
    verification_sent_at = models.DateTimeField(null=True, blank=True, editable=False)
    verification_expires_at = models.DateTimeField(null=True, blank=True, editable=False)
    verification_attempts = models.PositiveSmallIntegerField(default=0, editable=False)
    is_banned = models.BooleanField(default=False, db_index=True)
    banned_at = models.DateTimeField(null=True, blank=True)
    ban_reason = models.CharField(max_length=255, blank=True)
    joined_at = models.DateTimeField(auto_now_add=True, db_index=True)
    last_seen_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-joined_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["publisher", "external_user_id"],
                name="unique_publisher_respondent_sid",
            ),
            models.UniqueConstraint(
                fields=["publisher", "email_hash"],
                name="unique_publisher_respondent_email",
            ),
        ]
        indexes = [
            models.Index(
                fields=["publisher", "is_banned", "-last_seen_at"],
                name="respondent_supplier_state_idx",
            ),
        ]

    @property
    def full_name(self):
        from .respondent_security import decrypt_respondent_value

        return decrypt_respondent_value(self.encrypted_name)

    @property
    def email(self):
        from .respondent_security import decrypt_respondent_value

        return decrypt_respondent_value(self.encrypted_email)

    @property
    def masked_email(self):
        value = self.email
        if "@" not in value:
            return "Email unavailable"
        local, domain = value.split("@", 1)
        visible = local[:2] if len(local) > 2 else local[:1]
        return f"{visible}{'•' * max(3, len(local) - len(visible))}@{domain}"

    def set_identity(self, *, full_name, email):
        from .respondent_security import (
            encrypt_respondent_value,
            normalize_respondent_email,
            respondent_email_hash,
        )

        normalized_email = normalize_respondent_email(email)
        self.encrypted_name = encrypt_respondent_value(str(full_name or "").strip())
        self.encrypted_email = encrypt_respondent_value(normalized_email)
        self.email_hash = respondent_email_hash(normalized_email)

    def __str__(self):
        return f"{self.publisher.slug} · {self.external_user_id}"


class WallVisit(models.Model):
    """Short-lived browser visit linked to a verified respondent when available."""

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    publisher = models.ForeignKey(Publisher, on_delete=models.PROTECT, related_name="wall_visits")
    placement = models.ForeignKey(
        PublisherPlacement,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="visits",
    )
    respondent = models.ForeignKey(
        RespondentProfile,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="visits",
    )
    external_user_id = models.CharField(max_length=160, db_index=True)
    external_campaign_id = models.CharField(max_length=160, blank=True)
    affiliate_sub_id = models.CharField(max_length=160, blank=True)
    affiliate_sub_id_3 = models.CharField(max_length=160, blank=True)
    affiliate_sub_id_4 = models.CharField(max_length=160, blank=True)
    affiliate_sub_id_5 = models.CharField(max_length=160, blank=True)
    idfa = models.CharField(max_length=160, blank=True)
    gaid = models.CharField(max_length=160, blank=True)
    entry_nonce = models.CharField(max_length=80)
    country_code = models.CharField(max_length=8, blank=True, db_index=True)
    device = models.CharField(max_length=40, blank=True)
    ip_hash = models.CharField(max_length=64, blank=True, db_index=True)
    user_agent = models.CharField(max_length=500, blank=True)
    entry_timestamp = models.DateTimeField()
    expires_at = models.DateTimeField(db_index=True)
    last_seen_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["publisher", "entry_nonce"], name="unique_publisher_wall_nonce")
        ]
        indexes = [
            models.Index(fields=["publisher", "external_user_id", "-created_at"], name="wall_visit_user_idx")
        ]

    def __str__(self):
        return f"{self.publisher.slug} · {self.external_user_id} · {self.public_id}"


class OfferClick(models.Model):
    """Immutable publisher/user/survey attribution for one respondent journey."""

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    visit = models.ForeignKey(WallVisit, on_delete=models.PROTECT, related_name="clicks")
    publisher = models.ForeignKey(Publisher, on_delete=models.PROTECT, related_name="offer_clicks")
    survey = models.ForeignKey("surveys.Survey", on_delete=models.PROTECT, related_name="offerwall_clicks")
    attempt = models.OneToOneField(
        "surveys.SurveyAttempt", on_delete=models.PROTECT, related_name="offerwall_click"
    )
    external_user_id = models.CharField(max_length=160, db_index=True)
    source_cpi_snapshot = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    payout_percent_snapshot = models.DecimalField(max_digits=5, decimal_places=2)
    payout_snapshot = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    currency = models.CharField(max_length=3, default="USD")
    status = models.CharField(max_length=20, default="initiated", db_index=True)
    is_verified = models.BooleanField(default=False, db_index=True)
    credited_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["visit", "survey"], name="unique_visit_offer_click")
        ]
        indexes = [
            models.Index(fields=["publisher", "external_user_id", "survey", "-created_at"], name="offer_click_user_idx")
        ]

    def __str__(self):
        return f"{self.publisher.slug} · {self.survey.local_id} · {self.external_user_id}"


class RewardLedgerEntry(models.Model):
    class EntryType(models.TextChoices):
        CREDIT = "credit", "Credit"
        REVERSAL = "reversal", "Reversal"

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    publisher = models.ForeignKey(Publisher, on_delete=models.PROTECT, related_name="reward_ledger")
    click = models.ForeignKey(OfferClick, on_delete=models.PROTECT, related_name="ledger_entries")
    survey = models.ForeignKey("surveys.Survey", on_delete=models.PROTECT, related_name="offerwall_ledger")
    external_user_id = models.CharField(max_length=160, db_index=True)
    entry_type = models.CharField(max_length=12, choices=EntryType.choices, db_index=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3)
    idempotency_key = models.CharField(max_length=160, unique=True)
    reason = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["click", "entry_type"], name="unique_click_ledger_type"),
            models.UniqueConstraint(
                fields=["publisher", "external_user_id", "survey"],
                condition=models.Q(entry_type="credit"),
                name="unique_publisher_user_offer_credit",
            ),
        ]

    @property
    def signed_amount(self):
        return -self.amount if self.entry_type == self.EntryType.REVERSAL else self.amount

    def __str__(self):
        return f"{self.entry_type} · {self.amount} {self.currency} · {self.public_id}"


class PublisherPayoutRequest(models.Model):
    """Publisher withdrawal with reserved-balance and staff review state."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending review"
        APPROVED = "approved", "Approved"
        PROCESSING = "processing", "Processing"
        PAID = "paid", "Paid"
        REJECTED = "rejected", "Rejected"
        CANCELED = "canceled", "Canceled"

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    publisher = models.ForeignKey(
        Publisher, on_delete=models.PROTECT, related_name="payout_requests"
    )
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(Decimal("0.01"))],
    )
    currency = models.CharField(max_length=3)
    status = models.CharField(
        max_length=12, choices=Status.choices, default=Status.PENDING, db_index=True
    )
    payout_method = models.CharField(max_length=80)
    publisher_note = models.CharField(max_length=500, blank=True)
    admin_note = models.CharField(max_length=500, blank=True)
    payment_reference = models.CharField(max_length=160, blank=True)
    available_balance_snapshot = models.DecimalField(max_digits=12, decimal_places=2)
    requested_at = models.DateTimeField(auto_now_add=True, db_index=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    paid_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reviewed_offerwall_payouts",
    )

    class Meta:
        ordering = ["-requested_at"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(amount__gt=0), name="offerwall_payout_positive_amount"
            )
        ]
        indexes = [
            models.Index(
                fields=["publisher", "status", "-requested_at"],
                name="publisher_payout_status_idx",
            )
        ]

    def __str__(self):
        return f"{self.publisher.slug} · {self.amount} {self.currency} · {self.status}"


class PostbackDelivery(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        DELIVERED = "delivered", "Delivered"
        FAILED = "failed", "Failed"
        SKIPPED = "skipped", "Skipped"

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    publisher = models.ForeignKey(Publisher, on_delete=models.PROTECT, related_name="postback_deliveries")
    placement = models.ForeignKey(
        PublisherPlacement,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="postback_deliveries",
    )
    click = models.ForeignKey(OfferClick, on_delete=models.PROTECT, related_name="postback_deliveries")
    ledger_entry = models.ForeignKey(
        RewardLedgerEntry,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="postback_deliveries",
    )
    event_type = models.CharField(max_length=32)
    callback_url = models.URLField(max_length=2000, blank=True)
    payload = models.JSONField(default=dict)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.PENDING, db_index=True)
    attempt_count = models.PositiveIntegerField(default=0)
    response_code = models.PositiveSmallIntegerField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    next_attempt_at = models.DateTimeField(null=True, blank=True, db_index=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["click", "event_type"], name="unique_click_postback_event")
        ]
        indexes = [models.Index(fields=["status", "next_attempt_at"], name="postback_retry_idx")]

    def __str__(self):
        return f"{self.publisher.slug} · {self.event_type} · {self.status}"
