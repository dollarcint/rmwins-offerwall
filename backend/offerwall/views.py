"""Public signed wall, offer clicks, result pages and publisher inventory API."""

import re
import secrets
from datetime import datetime, timezone as datetime_timezone
from decimal import Decimal

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.decorators import user_passes_test
from django.core.cache import caches
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.text import slugify
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from accounts.throttling import (
    consume_login_attempt,
    login_request_body_too_large,
    reset_login_account_attempts,
)
from surveys.models import Survey, SurveyAttempt

from .forms import SupplierLoginForm, SupplierSignupForm
from .models import (
    OfferClick,
    PostbackDelivery,
    Publisher,
    PublisherPortalAccount,
    PublisherPayoutRequest,
    RewardLedgerEntry,
    WallVisit,
)
from .security import (
    digest_api_key,
    generate_signing_secret,
    verify_click_signature,
    verify_entry_signature,
    verify_portal_access,
    verify_result_signature,
    verify_session_signature,
)
from .services import (
    create_api_visit,
    create_offer_click,
    create_wall_visit,
    offer_catalog,
    process_attempt_outcome,
    review_publisher_registration,
    result_url,
    session_url,
)
from .wallet import request_withdrawal, transition_payout, wallet_summary


USER_ID_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,160}$")
PORTAL_SESSION_KEY = "offerwall_publisher_id"
SUPPLIER_ACCOUNT_SESSION_KEY = "offerwall_supplier_publisher_id"


def _registration_slug(company_name: str) -> str:
    base = slugify(company_name)[:48] or "supplier"
    if not base[0].isalpha():
        base = f"supplier-{base}"[:48]
    for _ in range(10):
        candidate = f"{base}-{secrets.token_hex(3)}"
        if not Publisher.objects.filter(slug=candidate).exists():
            return candidate
    raise ValidationError("A supplier code could not be generated. Please try again.")


def _no_store(response):
    response["Cache-Control"] = "no-store, private, max-age=0"
    response["Pragma"] = "no-cache"
    return response


def _error(request, title, message, *, status=400):
    return _no_store(
        render(
            request,
            "offerwall/error.html",
            {"title": title, "message": message},
            status=status,
        )
    )


def _rate_limited(request, scope: str, limit: int) -> bool:
    forwarded = request.META.get("REMOTE_ADDR", "unknown")
    bucket = int(timezone.now().timestamp()) // 60
    key = f"offerwall-rate:{scope}:{forwarded}:{bucket}"
    cache = caches["default"]
    try:
        if cache.add(key, 1, timeout=90):
            return False
        return cache.incr(key) > limit
    except Exception:
        return False


@require_GET
def landing(request):
    return _no_store(
        render(
            request,
            "offerwall/landing.html",
            {
                "active_publishers": Publisher.objects.filter(is_active=True).count(),
                "active_offers": Survey.objects.filter(
                    status=Survey.Status.LIVE, remaining__gt=0, cpi__gt=0
                ).count(),
            },
        )
    )


def _supplier_account(request):
    publisher_id = str(request.session.get(SUPPLIER_ACCOUNT_SESSION_KEY) or "").strip()
    if not publisher_id:
        return None
    account = (
        PublisherPortalAccount.objects.select_related("publisher", "user")
        .filter(publisher__public_id=publisher_id)
        .first()
    )
    if not account or not account.user.is_active:
        request.session.pop(SUPPLIER_ACCOUNT_SESSION_KEY, None)
        return None
    return account


@require_http_methods(["GET", "POST"])
def supplier_login(request):
    existing_account = _supplier_account(request)
    if existing_account:
        return HttpResponseRedirect(reverse("offerwall:publisher-dashboard"))

    if request.method == "POST":
        if login_request_body_too_large(request):
            return _error(request, "Login request too large", "Please try again.", status=413)
        form = SupplierLoginForm(request.POST)
        identity = str(request.POST.get("identity") or "").strip()
        user_record = (
            get_user_model()
            .objects.filter(Q(username__iexact=identity) | Q(email__iexact=identity))
            .first()
        )
        throttle_identity = user_record.username if user_record else identity
        if not consume_login_attempt(request, throttle_identity):
            response = _error(
                request,
                "Too many login attempts",
                "Please wait a few minutes and try again.",
                status=429,
            )
            response["Retry-After"] = str(settings.AUTH_LOGIN_WINDOW_SECONDS)
            return response
        if form.is_valid():
            identity = form.cleaned_data["identity"].strip()
            username = user_record.username if user_record else identity
            user = authenticate(
                request,
                username=username,
                password=form.cleaned_data["password"],
            )
            account = (
                PublisherPortalAccount.objects.select_related("publisher")
                .filter(user=user)
                .first()
                if user
                else None
            )
            if account:
                request.session.cycle_key()
                request.session.pop(PORTAL_SESSION_KEY, None)
                request.session[SUPPLIER_ACCOUNT_SESSION_KEY] = str(
                    account.publisher.public_id
                )
                reset_login_account_attempts(throttle_identity)
                if form.cleaned_data.get("remember_me"):
                    request.session.set_expiry(settings.OFFERWALL_PORTAL_SESSION_TTL_SECONDS)
                else:
                    request.session.set_expiry(0)
                return HttpResponseRedirect(reverse("offerwall:publisher-dashboard"))
            form.add_error(None, "Username/email or password is incorrect.")
    else:
        form = SupplierLoginForm()
    return _no_store(render(request, "offerwall/supplier_login.html", {"form": form}))


@require_http_methods(["GET", "POST"])
def supplier_signup(request):
    existing_account = _supplier_account(request)
    if existing_account:
        return HttpResponseRedirect(reverse("offerwall:publisher-dashboard"))

    if request.method == "POST":
        if login_request_body_too_large(request):
            return _error(request, "Registration request too large", "Please try again.", status=413)
        form = SupplierSignupForm(request.POST)
        if _rate_limited(
            request,
            "supplier-signup",
            settings.OFFERWALL_SIGNUP_RATE_LIMIT_PER_MINUTE,
        ):
            return _error(
                request,
                "Too many registrations",
                "Please wait a minute and try again.",
                status=429,
            )
        if form.is_valid():
            data = form.cleaned_data
            with transaction.atomic():
                user = get_user_model().objects.create_user(
                    username=data["username"],
                    email=data["business_email"],
                    password=data["password1"],
                    first_name=data["contact_name"][:150],
                    is_active=True,
                    is_staff=False,
                    is_superuser=False,
                )
                publisher = Publisher.objects.create(
                    name=data["company_name"],
                    slug=_registration_slug(data["company_name"]),
                    is_active=False,
                )
                PublisherPortalAccount.objects.create(
                    user=user,
                    publisher=publisher,
                    contact_name=data["contact_name"],
                    business_email=data["business_email"],
                    phone=data["phone"],
                    website=data["website"],
                    country=data["country"],
                )
            request.session.cycle_key()
            request.session.pop(PORTAL_SESSION_KEY, None)
            request.session[SUPPLIER_ACCOUNT_SESSION_KEY] = str(publisher.public_id)
            request.session.set_expiry(settings.OFFERWALL_PORTAL_SESSION_TTL_SECONDS)
            messages.success(
                request,
                "Registration submitted. RM Wins will review your supplier account.",
            )
            return HttpResponseRedirect(reverse("offerwall:publisher-dashboard"))
    else:
        form = SupplierSignupForm()
    return _no_store(render(request, "offerwall/supplier_signup.html", {"form": form}))


def _offerwall_operator(user):
    return bool(user.is_authenticated and user.is_active and user.is_staff)


@user_passes_test(_offerwall_operator, login_url="/login/")
@require_GET
def offerwall_operations(request):
    registrations = PublisherPortalAccount.objects.select_related(
        "publisher", "user", "reviewed_by"
    )[:50]
    publishers = Publisher.objects.select_related("portal_account__user").order_by(
        "-updated_at"
    )[:50]
    payout_requests = PublisherPayoutRequest.objects.select_related(
        "publisher", "reviewed_by"
    )[:50]
    recent_rewards = RewardLedgerEntry.objects.select_related(
        "publisher", "survey"
    )[:25]
    postbacks = PostbackDelivery.objects.select_related("publisher", "click")[:25]
    context = {
        "active_page": "offerwall-operations",
        "registrations": registrations,
        "publishers": publishers,
        "payout_requests": payout_requests,
        "recent_rewards": recent_rewards,
        "postbacks": postbacks,
        "operation_counts": {
            "pending_registrations": PublisherPortalAccount.objects.filter(
                status=PublisherPortalAccount.Status.PENDING
            ).count(),
            "active_publishers": Publisher.objects.filter(is_active=True).count(),
            "pending_payouts": PublisherPayoutRequest.objects.filter(
                status__in=(
                    PublisherPayoutRequest.Status.PENDING,
                    PublisherPayoutRequest.Status.APPROVED,
                    PublisherPayoutRequest.Status.PROCESSING,
                )
            ).count(),
            "failed_postbacks": PostbackDelivery.objects.filter(
                status=PostbackDelivery.Status.FAILED
            ).count(),
        },
    }
    return _no_store(render(request, "offerwall/operations.html", context))


@user_passes_test(_offerwall_operator, login_url="/login/")
@require_POST
def offerwall_operations_action(request):
    action = str(request.POST.get("action") or "").strip()
    try:
        if action in {"approve-registration", "reject-registration"}:
            account = get_object_or_404(
                PublisherPortalAccount, pk=request.POST.get("registration_id")
            )
            status = (
                PublisherPortalAccount.Status.APPROVED
                if action == "approve-registration"
                else PublisherPortalAccount.Status.REJECTED
            )
            review_publisher_registration(
                account,
                status,
                reviewer=request.user,
                admin_note=request.POST.get("admin_note", ""),
            )
            messages.success(
                request,
                f"{account.publisher.name} registration marked {status}.",
            )
        elif action == "toggle-publisher":
            publisher = get_object_or_404(Publisher, pk=request.POST.get("publisher_id"))
            supplier_account = getattr(publisher, "portal_account", None)
            if (
                supplier_account
                and supplier_account.status
                != PublisherPortalAccount.Status.APPROVED
            ):
                review_publisher_registration(
                    supplier_account,
                    PublisherPortalAccount.Status.APPROVED,
                    reviewer=request.user,
                    admin_note="Publisher enabled from Offerwall Operations.",
                )
                messages.success(
                    request,
                    f"{publisher.name} registration approved and publisher enabled.",
                )
            else:
                publisher.is_active = not publisher.is_active
                publisher.save(update_fields=["is_active", "updated_at"])
                messages.success(
                    request,
                    f"{publisher.name} is now {'active' if publisher.is_active else 'inactive'}.",
                )
        elif action == "rotate-api-key":
            publisher = get_object_or_404(Publisher, pk=request.POST.get("publisher_id"))
            raw_key = publisher.rotate_api_key()
            publisher.save(
                update_fields=[
                    "api_key_hash",
                    "api_key_prefix",
                    "api_key_last_four",
                    "api_key_changed_at",
                    "api_key_last_used_at",
                    "updated_at",
                ]
            )
            messages.warning(
                request,
                f"Copy this API key now; it is shown once: {raw_key}",
            )
        elif action == "rotate-signing-secret":
            publisher = get_object_or_404(Publisher, pk=request.POST.get("publisher_id"))
            raw_secret = generate_signing_secret()
            publisher.set_signing_secret(raw_secret)
            publisher.save(
                update_fields=[
                    "encrypted_signing_secret",
                    "signing_secret_last_four",
                    "signing_secret_changed_at",
                    "updated_at",
                ]
            )
            messages.warning(
                request,
                f"Copy this signing secret now; it is shown once: {raw_secret}",
            )
        elif action.startswith("payout-"):
            payout = get_object_or_404(
                PublisherPayoutRequest, pk=request.POST.get("payout_id")
            )
            status_map = {
                "payout-approve": PublisherPayoutRequest.Status.APPROVED,
                "payout-process": PublisherPayoutRequest.Status.PROCESSING,
                "payout-paid": PublisherPayoutRequest.Status.PAID,
                "payout-reject": PublisherPayoutRequest.Status.REJECTED,
                "payout-cancel": PublisherPayoutRequest.Status.CANCELED,
            }
            if action not in status_map:
                raise ValidationError("Unknown payout action.")
            transition_payout(
                payout,
                status_map[action],
                reviewer=request.user,
                payment_reference=request.POST.get("payment_reference", ""),
                admin_note=request.POST.get("admin_note", ""),
            )
            messages.success(request, f"Payout moved to {status_map[action]}.")
        elif action == "retry-postback":
            delivery = get_object_or_404(
                PostbackDelivery.objects.select_related("publisher"),
                pk=request.POST.get("postback_id"),
            )
            if not delivery.publisher.postback_enabled or not delivery.publisher.callback_url:
                raise ValidationError("Publisher postbacks are not enabled.")
            from .tasks import deliver_postback_task

            delivery.status = PostbackDelivery.Status.PENDING
            delivery.next_attempt_at = None
            delivery.save(update_fields=["status", "next_attempt_at", "updated_at"])
            deliver_postback_task.delay(delivery.pk)
            messages.success(request, "Postback queued for retry.")
        else:
            raise ValidationError("Unknown Offerwall operation.")
    except (ValidationError, ValueError) as exc:
        message = " ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc)
        messages.error(request, message)
    return HttpResponseRedirect(reverse("offerwall:operations"))


@require_GET
def wall_entry(request, publisher_slug):
    if _rate_limited(request, "entry", settings.OFFERWALL_ENTRY_RATE_LIMIT_PER_MINUTE):
        return _error(request, "Too many requests", "Please wait a minute and try again.", status=429)
    publisher = get_object_or_404(Publisher, slug=publisher_slug, is_active=True)
    external_user_id = str(request.GET.get("uid") or "").strip()
    nonce = str(request.GET.get("nonce") or "").strip()
    signature = str(request.GET.get("sig") or "").strip()
    timestamp_value = str(request.GET.get("ts") or "").strip()
    if not USER_ID_RE.fullmatch(external_user_id) or not timestamp_value.isdigit():
        return _error(request, "Invalid offerwall link", "The signed publisher link is incomplete.")
    timestamp = int(timestamp_value)
    if not verify_entry_signature(
        publisher,
        external_user_id=external_user_id,
        timestamp=timestamp,
        nonce=nonce,
        signature=signature,
    ):
        return _error(request, "Invalid offerwall link", "The publisher signature is invalid.", status=403)

    now = timezone.now()
    existing = WallVisit.objects.filter(publisher=publisher, entry_nonce=nonce).first()
    age_seconds = int(now.timestamp()) - timestamp
    outside_entry_window = (
        age_seconds > settings.OFFERWALL_ENTRY_TTL_SECONDS
        or age_seconds < -settings.OFFERWALL_ENTRY_FUTURE_SKEW_SECONDS
    )
    if outside_entry_window and not (
        existing
        and existing.external_user_id == external_user_id
        and existing.expires_at > now
    ):
        return _error(request, "Offerwall link expired", "Request a fresh signed link from the publisher.", status=403)
    try:
        entry_at = datetime.fromtimestamp(timestamp, tz=datetime_timezone.utc)
        visit = create_wall_visit(
            publisher,
            external_user_id=external_user_id,
            nonce=nonce,
            entry_timestamp=entry_at,
            request=request,
        )
    except (OverflowError, OSError, ValueError) as exc:
        return _error(request, "Invalid offerwall session", str(exc), status=403)
    return _no_store(HttpResponseRedirect(session_url(visit)))


def _active_visit_or_error(request, visit_id, signature):
    visit = get_object_or_404(
        WallVisit.objects.select_related("publisher"), public_id=visit_id
    )
    if not visit.publisher.is_active:
        return None, _error(request, "Offerwall unavailable", "This publisher is inactive.", status=403)
    if visit.expires_at <= timezone.now():
        return None, _error(request, "Offerwall session expired", "Request a fresh link from the publisher.", status=403)
    if not verify_session_signature(visit.publisher, visit.public_id, signature):
        return None, _error(request, "Invalid offerwall session", "The session signature is invalid.", status=403)
    WallVisit.objects.filter(pk=visit.pk).update(last_seen_at=timezone.now())
    return visit, None


@require_GET
def wall_session(request, visit_id):
    visit, error = _active_visit_or_error(request, visit_id, request.GET.get("sig", ""))
    if error:
        return error
    offers = offer_catalog(visit.publisher, visit)
    response = render(
        request,
        "offerwall/wall.html",
        {
            "publisher": visit.publisher,
            "visit": visit,
            "offers": offers,
            "offer_count": len(offers),
        },
    )
    return _no_store(response)


@require_GET
def click_offer(request, visit_id, survey_id):
    visit = get_object_or_404(
        WallVisit.objects.select_related("publisher"), public_id=visit_id
    )
    if visit.expires_at <= timezone.now() or not visit.publisher.is_active:
        return _error(request, "Offer unavailable", "This offerwall session has expired.", status=403)
    if not verify_click_signature(
        visit.publisher, visit.public_id, survey_id, request.GET.get("sig", "")
    ):
        return _error(request, "Invalid offer link", "The offer signature is invalid.", status=403)
    survey = get_object_or_404(Survey.objects.select_related("client", "integration"), local_id=survey_id)
    try:
        click, created = create_offer_click(visit=visit, survey=survey, request=request)
    except ValueError as exc:
        return _error(request, "Offer unavailable", str(exc), status=409)
    if not created and click.attempt.status != SurveyAttempt.Status.INITIATED:
        return _no_store(HttpResponseRedirect(result_url(click)))
    return _no_store(
        HttpResponseRedirect(f"{reverse('survey-start')}?rid={click.attempt.rid}")
    )


@require_GET
def result(request, click_id):
    click = get_object_or_404(
        OfferClick.objects.select_related("publisher", "survey", "attempt", "visit"),
        public_id=click_id,
    )
    if not verify_result_signature(click.publisher, click.public_id, request.GET.get("sig", "")):
        return _error(request, "Invalid result link", "The result signature is invalid.", status=403)
    process_attempt_outcome(click.attempt_id)
    click.refresh_from_db()
    credit = RewardLedgerEntry.objects.filter(
        click=click, entry_type=RewardLedgerEntry.EntryType.CREDIT
    ).first()
    state = "pending"
    title = "Result pending"
    message = "The provider result is still being verified. No reward has been credited yet."
    if click.status == SurveyAttempt.Status.COMPLETED and credit:
        state = "success"
        title = "Offer completed"
        message = "The verified completion was credited successfully."
    elif click.status == SurveyAttempt.Status.COMPLETED:
        title = "Completion awaiting verification"
        message = "The completion has not produced a new verified credit yet."
    elif click.status in {
        SurveyAttempt.Status.TERMINATED,
        SurveyAttempt.Status.OVER_QUOTA,
        SurveyAttempt.Status.QUALITY_TERMINATED,
    }:
        state = "no-credit"
        title = click.attempt.get_status_display()
        message = "This attempt did not qualify for a reward. You can choose another offer."
    response = render(
        request,
        "offerwall/result.html",
        {
            "click": click,
            "credit": credit,
            "state": state,
            "title": title,
            "message": message,
            "wall_url": session_url(click.visit) if click.visit.expires_at > timezone.now() else "",
        },
    )
    return _no_store(response)


def _publisher_from_api_key(request):
    raw_key = str(request.headers.get("X-Offerwall-Key") or "").strip()
    if not 20 <= len(raw_key) <= 200:
        return None
    publisher = Publisher.objects.filter(
        api_key_hash=digest_api_key(raw_key), is_active=True
    ).first()
    if publisher:
        Publisher.objects.filter(pk=publisher.pk).update(api_key_last_used_at=timezone.now())
    return publisher


@require_GET
def offers_api(request):
    if _rate_limited(request, "api", settings.OFFERWALL_API_RATE_LIMIT_PER_MINUTE):
        return _no_store(JsonResponse({"error": "Rate limit exceeded."}, status=429))
    publisher = _publisher_from_api_key(request)
    if not publisher:
        return _no_store(JsonResponse({"error": "Invalid Offerwall API key."}, status=401))
    external_user_id = str(request.GET.get("uid") or "").strip()
    if not USER_ID_RE.fullmatch(external_user_id):
        return _no_store(JsonResponse({"error": "A valid uid is required."}, status=400))
    visit = create_api_visit(publisher, external_user_id=external_user_id, request=request)
    offers = offer_catalog(publisher, visit)
    response_offers = [
        {
            **item,
            "reward": str(item["reward"] if item["reward"] is not None else Decimal("0.00")),
            "incidence_rate": str(item["incidence_rate"]) if item["incidence_rate"] is not None else None,
            "click_url": request.build_absolute_uri(item["click_url"]),
        }
        for item in offers
    ]
    return _no_store(
        JsonResponse(
            {
                "publisher": {
                    "name": publisher.name,
                    "slug": publisher.slug,
                    "currency": publisher.currency,
                },
                "user_id": external_user_id,
                "session_url": session_url(visit),
                "expires_at": visit.expires_at.isoformat(),
                "offers": response_offers,
            }
        )
    )


def _portal_publisher(request):
    public_id = str(request.session.get(PORTAL_SESSION_KEY) or "").strip()
    if public_id:
        publisher = Publisher.objects.filter(public_id=public_id, is_active=True).first()
        if not publisher:
            request.session.pop(PORTAL_SESSION_KEY, None)
        else:
            return publisher
    account = _supplier_account(request)
    if (
        account
        and account.status == PublisherPortalAccount.Status.APPROVED
        and account.publisher.is_active
    ):
        return account.publisher
    return None


@require_GET
def publisher_access(request, publisher_slug):
    if _rate_limited(request, "portal-access", settings.OFFERWALL_ENTRY_RATE_LIMIT_PER_MINUTE):
        return _error(request, "Too many requests", "Please wait a minute and try again.", status=429)
    publisher = get_object_or_404(Publisher, slug=publisher_slug, is_active=True)
    timestamp_value = str(request.GET.get("ts") or "").strip()
    nonce = str(request.GET.get("nonce") or "").strip()
    signature = str(request.GET.get("sig") or "").strip()
    if not timestamp_value.isdigit():
        return _error(request, "Invalid publisher access", "The signed portal link is incomplete.")
    timestamp = int(timestamp_value)
    age_seconds = int(timezone.now().timestamp()) - timestamp
    if (
        age_seconds > settings.OFFERWALL_PORTAL_LINK_TTL_SECONDS
        or age_seconds < -settings.OFFERWALL_ENTRY_FUTURE_SKEW_SECONDS
        or not verify_portal_access(
            publisher, timestamp=timestamp, nonce=nonce, signature=signature
        )
    ):
        return _error(request, "Invalid publisher access", "The signed portal link is invalid or expired.", status=403)
    current = _portal_publisher(request)
    if not current or current.pk != publisher.pk:
        cache_key = f"offerwall-portal-nonce:{publisher.pk}:{nonce}"
        try:
            accepted = caches["default"].add(
                cache_key,
                1,
                timeout=settings.OFFERWALL_PORTAL_LINK_TTL_SECONDS + 60,
            )
        except Exception:
            return _error(
                request,
                "Publisher access unavailable",
                "Secure access verification is temporarily unavailable.",
                status=503,
            )
        if not accepted:
            return _error(request, "Publisher link already used", "Request a fresh portal link.", status=403)
        request.session.cycle_key()
        request.session[PORTAL_SESSION_KEY] = str(publisher.public_id)
        request.session.set_expiry(settings.OFFERWALL_PORTAL_SESSION_TTL_SECONDS)
    return _no_store(HttpResponseRedirect(reverse("offerwall:publisher-dashboard")))


@require_GET
def publisher_dashboard(request):
    supplier_account = _supplier_account(request)
    if supplier_account and (
        supplier_account.status != PublisherPortalAccount.Status.APPROVED
        or not supplier_account.publisher.is_active
    ):
        return _no_store(
            render(
                request,
                "offerwall/supplier_status.html",
                {
                    "portal_publisher": supplier_account.publisher,
                    "supplier_account": supplier_account,
                },
            )
        )
    publisher = _portal_publisher(request)
    if not publisher:
        return _error(
            request,
            "Publisher access required",
            "Open a fresh signed dashboard link supplied by RM Wins.",
            status=403,
        )
    wallet = wallet_summary(publisher)
    stats = publisher.offer_clicks.aggregate(
        clicks=Count("id"),
        users=Count("external_user_id", distinct=True),
        verified_completes=Count(
            "id",
            filter=Q(
                status=SurveyAttempt.Status.COMPLETED,
                is_verified=True,
            ),
        ),
    )
    response = render(
        request,
        "offerwall/publisher_dashboard.html",
        {
            "portal_publisher": publisher,
            "wallet": wallet,
            "stats": stats,
            "ledger_entries": publisher.reward_ledger.select_related("survey")[:25],
            "payout_requests": publisher.payout_requests.all()[:20],
            "payout_methods": ("Bank transfer", "PayPal", "Wise", "Other"),
        },
    )
    return _no_store(response)


@require_POST
def publisher_request_withdrawal(request):
    publisher = _portal_publisher(request)
    if not publisher:
        return _error(request, "Publisher access required", "Your portal session has expired.", status=403)
    try:
        payout = request_withdrawal(
            publisher,
            amount=request.POST.get("amount"),
            payout_method=request.POST.get("payout_method"),
            publisher_note=request.POST.get("publisher_note"),
        )
    except ValidationError as exc:
        messages.error(request, " ".join(exc.messages))
    else:
        messages.success(
            request,
            f"Withdrawal {payout.public_id} was submitted for review.",
        )
    return _no_store(HttpResponseRedirect(reverse("offerwall:publisher-dashboard")))


@require_POST
def publisher_logout(request):
    request.session.pop(PORTAL_SESSION_KEY, None)
    request.session.pop(SUPPLIER_ACCOUNT_SESSION_KEY, None)
    request.session.cycle_key()
    return _no_store(HttpResponseRedirect(reverse("home")))


@require_GET
def wallet_api(request):
    if _rate_limited(request, "wallet-api", settings.OFFERWALL_API_RATE_LIMIT_PER_MINUTE):
        return _no_store(JsonResponse({"error": "Rate limit exceeded."}, status=429))
    publisher = _publisher_from_api_key(request)
    if not publisher:
        return _no_store(JsonResponse({"error": "Invalid Offerwall API key."}, status=401))
    summary = wallet_summary(publisher)
    payouts = [
        {
            "id": str(item.public_id),
            "amount": str(item.amount),
            "currency": item.currency,
            "status": item.status,
            "payout_method": item.payout_method,
            "requested_at": item.requested_at.isoformat(),
            "paid_at": item.paid_at.isoformat() if item.paid_at else None,
        }
        for item in publisher.payout_requests.all()[:20]
    ]
    return _no_store(
        JsonResponse(
            {
                "publisher": publisher.slug,
                "wallet": {
                    key: str(value) if isinstance(value, Decimal) else value
                    for key, value in summary.items()
                },
                "payout_requests": payouts,
            }
        )
    )
