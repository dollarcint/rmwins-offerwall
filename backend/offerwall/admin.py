import secrets

from django.conf import settings
from django.contrib import admin, messages
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html

from .forms import PublisherAdminForm
from .models import (
    OfferClick,
    OfferOverride,
    PostbackDelivery,
    Publisher,
    RewardLedgerEntry,
    WallVisit,
)
from .security import signed_entry_query
from .services import ensure_service_user


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
        "name",
        "slug",
        "payout_percent",
        "currency",
        "postback_enabled",
        "is_active",
        "masked_api_key_display",
        "updated_at",
    ]
    list_filter = ["is_active", "postback_enabled", "currency"]
    search_fields = ["name", "slug"]
    readonly_fields = [
        "public_id",
        "service_user",
        "masked_signing_secret_display",
        "masked_api_key_display",
        "test_wall_link",
        "signing_secret_changed_at",
        "api_key_changed_at",
        "api_key_last_used_at",
        "created_at",
        "updated_at",
    ]
    fieldsets = [
        ("Publisher", {"fields": ["name", "slug", "public_id", "service_user", "is_active"]}),
        ("Commercial", {"fields": ["payout_percent", "currency"]}),
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
        ("Integration preview", {"fields": ["test_wall_link"]}),
        ("Audit", {"fields": ["created_at", "updated_at"], "classes": ["collapse"]}),
    ]
    inlines = [OfferOverrideInline]

    @admin.display(description="Signing secret")
    def masked_signing_secret_display(self, obj):
        return obj.masked_signing_secret if obj and obj.pk else "Generated on first save"

    @admin.display(description="Inventory API key")
    def masked_api_key_display(self, obj):
        return obj.masked_api_key if obj and obj.pk else "Generated on first save"

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


@admin.register(OfferOverride)
class OfferOverrideAdmin(admin.ModelAdmin):
    list_display = ["publisher", "survey", "is_excluded", "featured", "payout_percent_override", "updated_at"]
    list_filter = ["publisher", "is_excluded", "featured"]
    search_fields = ["publisher__name", "publisher__slug", "survey__local_id", "survey__name"]
    autocomplete_fields = ["publisher", "survey"]


@admin.register(WallVisit)
class WallVisitAdmin(admin.ModelAdmin):
    list_display = ["public_id", "publisher", "external_user_id", "country_code", "device", "expires_at", "created_at"]
    list_filter = ["publisher", "country_code", "device", "created_at"]
    search_fields = ["external_user_id", "public_id", "entry_nonce"]
    readonly_fields = [field.name for field in WallVisit._meta.fields]


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

@admin.action(description="Retry selected pending/failed postbacks")
def retry_postbacks(modeladmin, request, queryset):
    from .tasks import deliver_postback_task

    queued = 0
    for delivery in queryset.exclude(status=PostbackDelivery.Status.DELIVERED):
        if delivery.publisher.postback_enabled and delivery.publisher.callback_url:
            delivery.status = PostbackDelivery.Status.PENDING
            delivery.next_attempt_at = None
            delivery.save(update_fields=["status", "next_attempt_at", "updated_at"])
            deliver_postback_task.delay(delivery.pk)
            queued += 1
    modeladmin.message_user(request, f"Queued {queued} postback(s).")


@admin.register(PostbackDelivery)
class PostbackDeliveryAdmin(admin.ModelAdmin):
    list_display = ["public_id", "publisher", "event_type", "status", "attempt_count", "response_code", "created_at"]
    list_filter = ["publisher", "event_type", "status", "created_at"]
    search_fields = ["public_id", "click__public_id", "click__external_user_id"]
    readonly_fields = [field.name for field in PostbackDelivery._meta.fields]
    actions = [retry_postbacks]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
