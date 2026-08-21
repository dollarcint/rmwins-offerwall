"""Offerwall publishers, sessions, click attribution and immutable rewards."""

import uuid
from decimal import Decimal

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models
from django.utils import timezone

from .security import (
    encrypt_signing_secret,
    generate_api_key,
    generate_signing_secret,
)


PERCENTAGE_VALIDATORS = [MinValueValidator(Decimal("0.00")), MaxValueValidator(Decimal("100.00"))]


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


class WallVisit(models.Model):
    """Short-lived, signed browser session without creating a respondent account."""

    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    publisher = models.ForeignKey(Publisher, on_delete=models.PROTECT, related_name="wall_visits")
    external_user_id = models.CharField(max_length=160, db_index=True)
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
