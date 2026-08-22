import secrets

from django.conf import settings
from django.contrib import admin, messages
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html

from .forms import PublisherAdminForm
from .models import (
    OfferClick,
    OfferOverride,
    PlacementEventPostback,
    PostbackDelivery,
    Publisher,
    PublisherPlacement,
    PublisherPortalAccount,
    PublisherPayoutRequest,
    RespondentProfile,
    RewardLedgerEntry,
    WallVisit,
)
from .security import signed_entry_query, signed_portal_query
from .services import ensure_service_user, review_publisher_registration
from .wallet import transition_payout, wallet_summary


admin.site.site_header = "RM Wins Offerwall Administration"
admin.site.site_title = "RM Wins Offerwall Admin"
admin.site.index_title = "Offerwall operations"


class OfferOverrideInline(admin.TabularInline):
    model = OfferOverride
    extra = 0
    autocomplete_fields = ["survey"]
    fields = ["survey", "is_excluded", "title_override", "payout_percent_override", "featured"]


@admin.register(Publisher)
class PublisherAdmin(admin.ModelAdmin):
    form = PublisherAdminForm
    list_display = [
        "publisher_number",
        "name",
        "slug",
        "payout_percent",
        "currency",
        "postback_enabled",
        "is_active",
        "masked_api_key_display",
        "wallet_balance_display",
        "updated_at",
    ]
    list_filter = ["is_active", "postback_enabled", "currency"]
    search_fields = ["name", "slug", "publisher_number", "public_id"]
    readonly_fields = [
        "publisher_number",
        "public_id",
        "service_user",
        "masked_signing_secret_display",
        "masked_api_key_display",
        "test_wall_link",
        "publisher_portal_link",
        "wallet_summary_display",
        "signing_secret_changed_at",
        "api_key_changed_at",
        "api_key_last_used_at",
        "created_at",
        "updated_at",
    ]
    fieldsets = [
        ("Publisher", {"fields": ["name", "slug", "publisher_number", "public_id", "service_user", "is_active"]}),
        (
            "Commercial",
            {"fields": ["payout_percent", "currency", "wallet_summary_display"]},
        ),
        ("Postback", {"fields": ["postback_enabled", "callback_url"]}),
        (
            "Credentials",
            {
                "fields": [
                    "masked_signing_secret_display",
                    "rotate_signing_secret",
                    "signing_secret_changed_at",
                    "masked_api_key_display",
                    "rotate_api_key",
                    "api_key_changed_at",
                    "api_key_last_used_at",
                ]
            },
        ),
        (
            "Integration preview",
            {"fields": ["test_wall_link", "publisher_portal_link"]},
        ),
        ("Audit", {"fields": ["created_at", "updated_at"], "classes": ["collapse"]}),
    ]
    inlines = [OfferOverrideInline]

    @admin.display(description="Signing secret")
    def masked_signing_secret_display(self, obj):
        return obj.masked_signing_secret if obj and obj.pk else "Generated on first save"

    @admin.display(description="Inventory API key")
    def masked_api_key_display(self, obj):
        return obj.masked_api_key if obj and obj.pk else "Generated on first save"

    @admin.display(description="Available wallet")
    def wallet_balance_display(self, obj):
        if not obj or not obj.pk:
            return "—"
        wallet = wallet_summary(obj)
        return f"{wallet['currency']} {wallet['available']:.2f}"

    @admin.display(description="Wallet summary")
    def wallet_summary_display(self, obj):
        if not obj or not obj.pk:
            return "Available after first save."
        wallet = wallet_summary(obj)
        return format_html(
            "Net earned: <strong>{} {:.2f}</strong> · Reserved: {} {:.2f} · Paid: {} {:.2f} · Available: <strong>{} {:.2f}</strong>",
            wallet["currency"],
            wallet["net_earnings"],
            wallet["currency"],
            wallet["reserved"],
            wallet["currency"],
            wallet["paid"],
            wallet["currency"],
            wallet["available"],
        )

    @admin.display(description="Signed preview link")
    def test_wall_link(self, obj):
        if not obj or not obj.pk:
            return "Save the publisher first."
        timestamp = int(timezone.now().timestamp())
        nonce = secrets.token_urlsafe(18)
        path = reverse("offerwall:entry", kwargs={"publisher_slug": obj.slug})
        query = signed_entry_query(
            obj,
            external_user_id="preview-user",
            timestamp=timestamp,
            nonce=nonce,
        )
        base = str(settings.OFFERWALL_PUBLIC_BASE_URL or settings.PUBLIC_APP_BASE_URL or "").rstrip("/")
        url = f"{base}{path}?{query}" if base else f"{path}?{query}"
        return format_html('<a href="{}" target="_blank" rel="noopener">Open 15-minute preview wall ↗</a>', url)

    @admin.display(description="Publisher wallet dashboard")
    def publisher_portal_link(self, obj):
        if not obj or not obj.pk:
            return "Save the publisher first."
        timestamp = int(timezone.now().timestamp())
        nonce = secrets.token_urlsafe(18)
        path = reverse("offerwall:publisher-access", kwargs={"publisher_slug": obj.slug})
        query = signed_portal_query(obj, timestamp=timestamp, nonce=nonce)
        base = str(settings.OFFERWALL_PUBLIC_BASE_URL or settings.PUBLIC_APP_BASE_URL or "").rstrip("/")
        url = f"{base}{path}?{query}" if base else f"{path}?{query}"
        return format_html(
            '<a href="{}" target="_blank" rel="noopener">Open one-time 15-minute publisher dashboard link ↗</a>',
            url,
        )

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        ensure_service_user(obj)
        signing_secret = getattr(obj, "_generated_signing_secret", "")
        api_key = getattr(obj, "_generated_api_key", "")
        if signing_secret:
            self.message_user(
                request,
                f"Copy this signing secret now; it is shown once: {signing_secret}",
                level=messages.WARNING,
            )
        if api_key:
            self.message_user(
                request,
                f"Copy this Offerwall API key now; it is shown once: {api_key}",
                level=messages.WARNING,
            )


def _review_supplier_registrations(modeladmin, request, queryset, status):
    count = 0
    for account in queryset:
        review_publisher_registration(account, status, reviewer=request.user)
        count += 1
    modeladmin.message_user(request, f"Updated {count} supplier registration(s).")


@admin.action(description="Approve selected supplier registrations")
def approve_supplier_registrations(modeladmin, request, queryset):
    _review_supplier_registrations(
        modeladmin, request, queryset, PublisherPortalAccount.Status.APPROVED
    )


@admin.action(description="Reject selected supplier registrations")
def reject_supplier_registrations(modeladmin, request, queryset):
    _review_supplier_registrations(
        modeladmin, request, queryset, PublisherPortalAccount.Status.REJECTED
    )


@admin.register(PublisherPortalAccount)
class PublisherPortalAccountAdmin(admin.ModelAdmin):
    list_display = [
        "publisher",
        "contact_name",
        "business_email",
        "country",
        "status",
        "created_at",
    ]
    list_filter = ["status", "country", "created_at"]
    search_fields = [
        "publisher__name",
        "publisher__slug",
        "contact_name",
        "user__username",
        "user__email",
    ]
    readonly_fields = [
        "user",
        "publisher",
        "contact_name",
        "business_email",
        "phone",
        "website",
        "country",
        "job_title",
        "address_line",
        "city",
        "state",
        "postal_code",
        "reviewed_by",
        "reviewed_at",
        "created_at",
        "updated_at",
    ]
    fields = [
        "status",
        "user",
        "publisher",
        "contact_name",
        "business_email",
        "phone",
        "website",
        "country",
        "job_title",
        "address_line",
        "city",
        "state",
        "postal_code",
        "admin_note",
        "reviewed_by",
        "reviewed_at",
        "created_at",
        "updated_at",
    ]
    actions = [approve_supplier_registrations, reject_supplier_registrations]

    def save_model(self, request, obj, form, change):
        previous_status = None
        if obj.pk:
            previous_status = type(obj).objects.filter(pk=obj.pk).values_list(
                "status", flat=True
            ).first()
        if previous_status != obj.status:
            obj.reviewed_by = request.user
            obj.reviewed_at = timezone.now()
        super().save_model(request, obj, form, change)
        should_be_active = obj.status == PublisherPortalAccount.Status.APPROVED
        Publisher.objects.filter(pk=obj.publisher_id).update(
            is_active=should_be_active,
            updated_at=timezone.now(),
        )


@admin.register(OfferOverride)
class OfferOverrideAdmin(admin.ModelAdmin):
    list_display = ["publisher", "survey", "is_excluded", "featured", "payout_percent_override", "updated_at"]
    list_filter = ["publisher", "is_excluded", "featured"]
    search_fields = ["publisher__name", "publisher__slug", "survey__local_id", "survey__name"]
    autocomplete_fields = ["publisher", "survey"]


@admin.register(WallVisit)
class WallVisitAdmin(admin.ModelAdmin):
    list_display = ["public_id", "publisher", "placement", "respondent", "external_user_id", "country_code", "device", "expires_at", "created_at"]
    list_filter = ["publisher", "placement", "country_code", "device", "created_at"]
    search_fields = ["external_user_id", "external_campaign_id", "affiliate_sub_id", "public_id", "entry_nonce"]
    readonly_fields = [field.name for field in WallVisit._meta.fields]


@admin.register(RespondentProfile)
class RespondentProfileAdmin(admin.ModelAdmin):
    list_display = [
        "external_user_id",
        "full_name_display",
        "email_display",
        "publisher",
        "last_placement",
        "age",
        "gender",
        "is_email_verified",
        "is_banned",
        "joined_at",
        "last_seen_at",
    ]
    list_filter = [
        "publisher",
        "is_email_verified",
        "is_banned",
        "gender",
        "first_placement",
        "last_placement",
        "joined_at",
    ]
    search_fields = ["external_user_id", "public_id", "email_hash"]
    readonly_fields = [
        "public_id",
        "full_name_display",
        "email_display",
        "email_hash",
        "verification_code_hash",
        "verification_sent_at",
        "verification_expires_at",
        "verification_attempts",
        "email_verified_at",
        "joined_at",
        "last_seen_at",
        "updated_at",
    ]
    fieldsets = [
        ("Identity", {"fields": ["publisher", "public_id", "external_user_id", "full_name_display", "email_display", "email_hash", "age", "gender"]}),
        ("Placement", {"fields": ["first_placement", "last_placement"]}),
        ("Verification", {"fields": ["is_email_verified", "email_verified_at", "verification_sent_at", "verification_expires_at", "verification_attempts", "verification_code_hash"]}),
        ("Access", {"fields": ["is_banned", "banned_at", "ban_reason"]}),
        ("Activity", {"fields": ["joined_at", "last_seen_at", "updated_at"]}),
    ]

    @admin.display(description="Name")
    def full_name_display(self, obj):
        return obj.full_name

    @admin.display(description="Email")
    def email_display(self, obj):
        return obj.email

    def has_add_permission(self, request):
        return False


@admin.register(PublisherPlacement)
class PublisherPlacementAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "publisher",
        "platform",
        "status",
        "postback_enabled",
        "currency_name",
        "updated_at",
    ]
    list_filter = ["publisher", "platform", "status", "traffic_type", "postback_enabled", "currency"]
    search_fields = ["name", "website_name", "website_url", "public_id"]
    readonly_fields = [
        "public_id",
        "masked_postback_secret_display",
        "postback_secret_changed_at",
        "created_at",
        "updated_at",
    ]
    fieldsets = [
        ("Placement", {"fields": ["publisher", "public_id", "name", "platform", "status"]}),
        ("Website", {"fields": ["website_name", "website_url", "allowed_domains", "traffic_type"]}),
        (
            "Reward",
            {
                "fields": [
                    "currency",
                    "currency_name",
                    "user_revenue_share",
                    "currency_multiplier",
                    "reward_rounding_precision",
                ]
            },
        ),
        ("Design", {"fields": ["active_content_types", "currency_icon", "header_logo"]}),
        (
            "Variable mapping",
            {"fields": ["respondent_id_parameter", "campaign_id_parameter", "affiliate_sub_parameter"]},
        ),
        (
            "Postback",
            {
                "fields": [
                    "postback_enabled",
                    "postback_url",
                    "whitelist_postback_ip",
                    "postback_email_opt_out",
                    "masked_postback_secret_display",
                    "postback_secret_changed_at",
                ]
            },
        ),
        ("Audit", {"fields": ["created_at", "updated_at"], "classes": ["collapse"]}),
    ]

    @admin.display(description="Postback signing key")
    def masked_postback_secret_display(self, obj):
        return obj.masked_postback_secret if obj and obj.pk else "Generated on first save"


@admin.register(PlacementEventPostback)
class PlacementEventPostbackAdmin(admin.ModelAdmin):
    list_display = ["placement", "survey", "event_type", "event_name", "is_active", "updated_at"]
    list_filter = ["placement__publisher", "placement", "event_type", "is_active"]
    search_fields = ["placement__name", "survey__local_id", "event_name", "callback_url"]
    autocomplete_fields = ["placement", "survey"]
    readonly_fields = ["public_id", "created_at", "updated_at"]


@admin.register(OfferClick)
class OfferClickAdmin(admin.ModelAdmin):
    list_display = ["public_id", "publisher", "external_user_id", "survey", "status", "is_verified", "payout_snapshot", "currency", "created_at"]
    list_filter = ["publisher", "status", "is_verified", "currency", "created_at"]
    search_fields = ["public_id", "external_user_id", "survey__local_id", "attempt__rid"]
    readonly_fields = [field.name for field in OfferClick._meta.fields]


@admin.register(RewardLedgerEntry)
class RewardLedgerEntryAdmin(admin.ModelAdmin):
    list_display = ["public_id", "publisher", "external_user_id", "survey", "entry_type", "amount", "currency", "created_at"]
    list_filter = ["publisher", "entry_type", "currency", "created_at"]
    search_fields = ["public_id", "external_user_id", "click__public_id", "survey__local_id", "idempotency_key"]
    readonly_fields = [field.name for field in RewardLedgerEntry._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


def _transition_selected(modeladmin, request, queryset, status):
    updated = 0
    errors = []
    for payout in queryset.select_related("publisher"):
        try:
            transition_payout(
                payout,
                status,
                reviewer=request.user,
                payment_reference=payout.payment_reference,
                admin_note=payout.admin_note,
            )
        except ValidationError as exc:
            errors.append(f"{payout.public_id}: {' '.join(exc.messages)}")
        else:
            updated += 1
    if updated:
        modeladmin.message_user(request, f"Updated {updated} payout request(s).")
    if errors:
        modeladmin.message_user(request, " | ".join(errors[:5]), level=messages.ERROR)


@admin.action(description="Approve selected pending payouts")
def approve_payouts(modeladmin, request, queryset):
    _transition_selected(modeladmin, request, queryset, PublisherPayoutRequest.Status.APPROVED)


@admin.action(description="Move selected approved payouts to processing")
def process_payouts(modeladmin, request, queryset):
    _transition_selected(modeladmin, request, queryset, PublisherPayoutRequest.Status.PROCESSING)


@admin.action(description="Mark selected processing payouts paid (reference required)")
def mark_payouts_paid(modeladmin, request, queryset):
    _transition_selected(modeladmin, request, queryset, PublisherPayoutRequest.Status.PAID)


@admin.action(description="Reject selected active payouts")
def reject_payouts(modeladmin, request, queryset):
    _transition_selected(modeladmin, request, queryset, PublisherPayoutRequest.Status.REJECTED)


@admin.action(description="Cancel selected pending/approved payouts")
def cancel_payouts(modeladmin, request, queryset):
    _transition_selected(modeladmin, request, queryset, PublisherPayoutRequest.Status.CANCELED)


@admin.register(PublisherPayoutRequest)
class PublisherPayoutRequestAdmin(admin.ModelAdmin):
    list_display = [
        "public_id",
        "publisher",
        "amount",
        "currency",
        "status",
        "payout_method",
        "requested_at",
        "paid_at",
    ]
    list_filter = ["status", "currency", "payout_method", "requested_at"]
    search_fields = [
        "public_id",
        "publisher__name",
        "publisher__slug",
        "payment_reference",
    ]
    readonly_fields = [
        "public_id",
        "publisher",
        "amount",
        "currency",
        "status",
        "payout_method",
        "publisher_note",
        "available_balance_snapshot",
        "requested_at",
        "reviewed_at",
        "paid_at",
        "updated_at",
        "reviewed_by",
    ]
    fields = [
        "public_id",
        "publisher",
        "amount",
        "currency",
        "status",
        "payout_method",
        "publisher_note",
        "available_balance_snapshot",
        "payment_reference",
        "admin_note",
        "requested_at",
        "reviewed_at",
        "paid_at",
        "updated_at",
        "reviewed_by",
    ]
    actions = [
        approve_payouts,
        process_payouts,
        mark_payouts_paid,
        reject_payouts,
        cancel_payouts,
    ]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

@admin.action(description="Retry selected pending/failed postbacks")
def retry_postbacks(modeladmin, request, queryset):
    from .tasks import deliver_postback_task

    queued = 0
    for delivery in queryset.exclude(status=PostbackDelivery.Status.DELIVERED).select_related("placement", "publisher"):
        placement_ready = bool(
            delivery.placement_id
            and delivery.placement.postback_enabled
            and delivery.placement.postback_url
        )
        publisher_ready = bool(
            not delivery.placement_id
            and delivery.publisher.postback_enabled
            and delivery.publisher.callback_url
        )
        if placement_ready or publisher_ready:
            delivery.status = PostbackDelivery.Status.PENDING
            delivery.next_attempt_at = None
            delivery.save(update_fields=["status", "next_attempt_at", "updated_at"])
            deliver_postback_task.delay(delivery.pk)
            queued += 1
    modeladmin.message_user(request, f"Queued {queued} postback(s).")


@admin.register(PostbackDelivery)
class PostbackDeliveryAdmin(admin.ModelAdmin):
    list_display = ["public_id", "publisher", "placement", "event_type", "status", "attempt_count", "response_code", "created_at"]
    list_filter = ["publisher", "placement", "event_type", "status", "created_at"]
    search_fields = ["public_id", "click__public_id", "click__external_user_id"]
    readonly_fields = [field.name for field in PostbackDelivery._meta.fields]
    actions = [retry_postbacks]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
