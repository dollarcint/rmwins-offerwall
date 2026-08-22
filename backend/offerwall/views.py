"""Public signed wall, offer clicks, result pages and publisher inventory API."""

import csv
import hashlib
import hmac
import logging
import mimetypes
import re
import secrets
import uuid
from datetime import datetime, time, timedelta, timezone as datetime_timezone
from decimal import Decimal
from urllib.parse import urlencode, urlparse

import requests
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.decorators import user_passes_test
from django.core import signing
from django.core.cache import caches
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Count, DecimalField, Max, Prefetch, Q, Sum, Value
from django.db.models.functions import Coalesce
from django.core.paginator import Paginator
from django.http import (
    FileResponse,
    Http404,
    HttpResponseRedirect,
    JsonResponse,
    StreamingHttpResponse,
)
from django.shortcuts import get_object_or_404, render
from django.templatetags.static import static
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.utils.text import slugify
from django.views.decorators.http import require_GET, require_http_methods, require_POST
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt

from accounts.throttling import (
    consume_login_attempt,
    login_request_body_too_large,
    reset_login_account_attempts,
)
from surveys.models import Survey, SurveyAttempt
from surveys.outcomes import provider_outcome

from .forms import (
    PlacementCurrencyForm,
    PlacementDesignForm,
    PlacementEventPostbackForm,
    PlacementGeneralForm,
    PlacementPostbackForm,
    PublisherPlacementCreateForm,
    RespondentOnboardingForm,
    RespondentVerificationForm,
    SupplierLoginForm,
    SupplierSignupForm,
)
from .models import (
    OfferClick,
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
from .security import (
    decrypt_api_key,
    decrypt_placement_postback_secret,
    digest_api_key,
    generate_signing_secret,
    verify_click_signature,
    verify_entry_signature,
    verify_portal_access,
    verify_result_signature,
    verify_session_signature,
)
from .tasks import _validated_callback_url
from .respondent_security import respondent_email_hash
from .respondent_services import issue_respondent_verification, verify_respondent_code
from .services import (
    _render_postback_url,
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
APP_ID_RE = re.compile(r"^(?:RMW_APP_|ID_)([0-9a-fA-F]{32})$")
PORTAL_SESSION_KEY = "offerwall_publisher_id"
SUPPLIER_ACCOUNT_SESSION_KEY = "offerwall_supplier_publisher_id"
RESPONDENT_STATE_SALT = "offerwall.respondent.onboarding.v1"
logger = logging.getLogger(__name__)


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


def _app_uuid_from_id(app_id):
    match = APP_ID_RE.fullmatch(str(app_id or "").strip())
    return uuid.UUID(hex=match.group(1)) if match else None


def _placement_frame_sources(placement):
    sources = []
    candidates = [placement.website_url, *placement.allowed_domain_list]
    for raw_value in candidates:
        value = str(raw_value or "").strip().lower().rstrip("/")
        if not value:
            continue
        wildcard = value.startswith("*.") or value.startswith("https://*.")
        if value.startswith("https://*."):
            parse_value = "https://" + value[len("https://*.") :]
        elif value.startswith("*."):
            parse_value = "https://" + value[2:]
        elif "://" not in value:
            parse_value = "https://" + value
        else:
            parse_value = value
        parsed = urlparse(parse_value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        host = parsed.hostname.lower()
        try:
            port = f":{parsed.port}" if parsed.port else ""
        except ValueError:
            continue
        source = f"{parsed.scheme}://{'*.' if wildcard else ''}{host}{port}"
        if source not in sources:
            sources.append(source)
    return sources


def _placement_referrer_allowed(placement, request):
    referer = str(request.headers.get("Referer") or "").strip()
    if not referer:
        return True
    parsed = urlparse(referer)
    referer_host = str(parsed.hostname or "").lower()
    if not referer_host:
        return False
    request_host = str(request.get_host() or "").split(":", 1)[0].lower()
    if referer_host == request_host:
        return True
    for source in _placement_frame_sources(placement):
        wildcard = source.startswith("https://*.") or source.startswith("http://*.")
        source_host = str(urlparse(source.replace("*.", "")).hostname or "").lower()
        if wildcard and referer_host.endswith(f".{source_host}"):
            return True
        if not wildcard and referer_host == source_host:
            return True
    return False


def _apply_placement_frame_policy(response, placement):
    sources = ["'self'", *_placement_frame_sources(placement)]
    response["Content-Security-Policy"] = f"frame-ancestors {' '.join(dict.fromkeys(sources))}"
    response["X-Robots-Tag"] = "noindex, nofollow"
    response.xframe_options_exempt = True
    return response


def _external_referrer_origin(request):
    referer = str(request.headers.get("Referer") or "").strip()
    parsed = urlparse(referer)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    request_host = str(request.get_host() or "").split(":", 1)[0].lower()
    if parsed.hostname.lower() == request_host:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _respondent_state(placement, external_user_id, parent_origin=""):
    return signing.dumps(
        {
            "placement": str(placement.public_id),
            "sid": external_user_id,
            "parent_origin": parent_origin,
        },
        salt=RESPONDENT_STATE_SALT,
        compress=True,
    )


def _respondent_state_is_valid(request, value, placement, external_user_id):
    try:
        payload = signing.loads(
            str(value or ""),
            salt=RESPONDENT_STATE_SALT,
            max_age=settings.OFFERWALL_RESPONDENT_STATE_TTL_SECONDS,
        )
    except signing.BadSignature:
        return False
    if payload.get("placement") != str(placement.public_id) or payload.get("sid") != external_user_id:
        return False
    parent_origin = str(payload.get("parent_origin") or "")
    if parent_origin and parent_origin not in _placement_frame_sources(placement):
        parsed = urlparse(parent_origin)
        allowed_wildcard = any(
            source.startswith(("https://*.", "http://*."))
            and parsed.hostname
            and parsed.hostname.endswith(
                f".{urlparse(source.replace('*.', '')).hostname}"
            )
            for source in _placement_frame_sources(placement)
        )
        if not allowed_wildcard:
            return False
    request._offerwall_parent_origin = parent_origin
    return True


def _respondent_gate_response(
    request,
    placement,
    external_user_id,
    *,
    mode,
    form,
    profile=None,
    notice="",
    status=200,
):
    parent_origin = getattr(request, "_offerwall_parent_origin", "")
    response = render(
        request,
        "offerwall/respondent_gate.html",
        {
            "placement": placement,
            "external_user_id": external_user_id,
            "respondent_state": _respondent_state(
                placement,
                external_user_id,
                parent_origin,
            ),
            "respondent_parent_origin": parent_origin,
            "respondent": profile,
            "mode": mode,
            "form": form,
            "notice": notice,
        },
        status=status,
    )
    return _no_store(_apply_placement_frame_policy(response, placement))


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
                    "encrypted_api_key",
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
                PostbackDelivery.objects.select_related("publisher", "placement"),
                pk=request.POST.get("postback_id"),
            )
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
            if not (placement_ready or publisher_ready):
                raise ValidationError("Placement or publisher postbacks are not enabled.")
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
        WallVisit.objects.select_related("publisher", "placement", "respondent"),
        public_id=visit_id,
    )
    if not visit.publisher.is_active:
        return None, _error(request, "Offerwall unavailable", "This publisher is inactive.", status=403)
    if visit.expires_at <= timezone.now():
        return None, _error(request, "Offerwall session expired", "Request a fresh link from the publisher.", status=403)
    if not verify_session_signature(visit.publisher, visit.public_id, signature):
        return None, _error(request, "Invalid offerwall session", "The session signature is invalid.", status=403)
    WallVisit.objects.filter(pk=visit.pk).update(last_seen_at=timezone.now())
    return visit, None


def _render_wall_response(request, visit):
    if visit.respondent_id and visit.respondent.is_banned:
        response = _error(
            request,
            "Account access paused",
            "This respondent account has been blocked by the supplier.",
            status=403,
        )
        if visit.placement:
            _apply_placement_frame_policy(response, visit.placement)
        return response
    offers = offer_catalog(visit.publisher, visit)
    placement = visit.placement
    header_logo_url = ""
    currency_icon_url = ""
    if placement and placement.header_logo:
        header_logo_url = reverse(
            "offerwall:placement-brand-asset",
            kwargs={"placement_id": placement.public_id, "kind": "header-logo"},
        )
    if placement and placement.currency_icon:
        currency_icon_url = reverse(
            "offerwall:placement-brand-asset",
            kwargs={"placement_id": placement.public_id, "kind": "currency-icon"},
        )
    response = render(
        request,
        "offerwall/wall.html",
        {
            "publisher": visit.publisher,
            "visit": visit,
            "offers": offers,
            "offer_count": len(offers),
            "placement": placement,
            "header_logo_url": header_logo_url,
            "currency_icon_url": currency_icon_url,
            "frame_parent_origin": getattr(
                request, "_offerwall_parent_origin", ""
            ),
        },
    )
    if placement:
        _apply_placement_frame_policy(response, placement)
    return _no_store(response)


@require_GET
def wall_session(request, visit_id):
    visit, error = _active_visit_or_error(request, visit_id, request.GET.get("sig", ""))
    if error:
        return error
    return _render_wall_response(request, visit)


@require_GET
def click_offer(request, visit_id, survey_id):
    visit = get_object_or_404(
        WallVisit.objects.select_related("publisher", "placement", "respondent"),
        public_id=visit_id,
    )
    if visit.respondent_id and visit.respondent.is_banned:
        return _error(
            request,
            "Account access paused",
            "This respondent account has been blocked by the supplier.",
            status=403,
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
        OfferClick.objects.select_related(
            "publisher", "survey", "attempt", "visit", "visit__placement"
        ),
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
    display_credit_amount = credit.amount if credit else None
    display_credit_currency = credit.currency if credit else ""
    if credit and click.visit.placement_id:
        display_credit_amount = click.visit.placement.display_reward(credit.amount)
        display_credit_currency = click.visit.placement.currency_name
    response = render(
        request,
        "offerwall/result.html",
        {
            "click": click,
            "credit": credit,
            "display_credit_amount": display_credit_amount,
            "display_credit_currency": display_credit_currency,
            "state": state,
            "title": title,
            "message": message,
            "wall_url": session_url(click.visit) if click.visit.expires_at > timezone.now() else "",
        },
    )
    return _no_store(response)


def _publisher_from_api_key(request):
    authorization = str(request.headers.get("Authorization") or "").strip()
    bearer_key = ""
    if authorization.lower().startswith("bearer "):
        bearer_key = authorization[7:].strip()
    raw_key = str(
        request.headers.get("X-Offerwall-Key")
        or bearer_key
        or request.GET.get("key")
        or ""
    ).strip()
    if not 20 <= len(raw_key) <= 200:
        return None
    publisher = Publisher.objects.filter(
        api_key_hash=digest_api_key(raw_key), is_active=True
    ).first()
    if publisher:
        Publisher.objects.filter(pk=publisher.pk).update(api_key_last_used_at=timezone.now())
    return publisher


def _placement_from_app_id(publisher, app_id):
    value = str(app_id or "").strip()
    if not value:
        return None
    placement_uuid = _app_uuid_from_id(value)
    if not placement_uuid:
        raise ValueError("Invalid app_id.")
    placement = PublisherPlacement.objects.filter(
        publisher=publisher,
        public_id=placement_uuid,
        status=PublisherPlacement.Status.ACTIVE,
    ).first()
    if not placement:
        raise ValueError("Unknown or inactive app_id.")
    return placement


@require_GET
def offers_api(request):
    if _rate_limited(request, "api", settings.OFFERWALL_API_RATE_LIMIT_PER_MINUTE):
        return _no_store(JsonResponse({"error": "Rate limit exceeded."}, status=429))
    publisher = _publisher_from_api_key(request)
    if not publisher:
        return _no_store(
            JsonResponse(
                {"message": "Invalid API key.", "type": 0, "code": 401}, status=401
            )
        )
    pubid = str(request.GET.get("pubid") or "").strip()
    if pubid not in {publisher.publisher_code, str(publisher.public_id)}:
        return _no_store(
            JsonResponse(
                {"message": "A valid pubid is required.", "type": 0, "code": 400},
                status=400,
            )
        )
    try:
        placement = _placement_from_app_id(publisher, request.GET.get("app_id"))
    except ValueError as exc:
        return _no_store(
            JsonResponse({"message": str(exc), "type": 0, "code": 400}, status=400)
        )
    if not placement:
        return _no_store(
            JsonResponse(
                {"message": "A valid app_id is required.", "type": 0, "code": 400},
                status=400,
            )
        )
    country = str(request.GET.get("country") or "All").strip().upper()
    platform = str(request.GET.get("platform") or "All").strip()
    device = "" if platform.casefold() == "all" else platform
    visit = WallVisit(
        public_id=uuid.uuid4(),
        publisher=publisher,
        external_user_id="{SID}",
        placement=placement,
        country_code="" if country == "ALL" else country,
        device=device,
    )
    offers = offer_catalog(publisher, visit)
    response_offers = []
    for item in offers:
        tracking_path = reverse("offerwall:offer-click-tracking")
        tracking_url = request.build_absolute_uri(tracking_path)
        tracking_url = (
            f"{tracking_url}?app_id={placement.app_id}&offer_id={item['id']}"
            "&uid={SID}&sid={YOUR_CLICK_ID}&sid2={YOUR_SOURCE_ID}"
        )
        payout = item["reward"] if item["reward"] is not None else Decimal("0.00")
        response_offers.append(
            {
                "offer_id": item["id"],
                "offer_name": item["title"],
                "offer_desc": None,
                "kpi": None,
                "traffic_type": placement.traffic_type,
                "call_to_action": "Complete the survey honestly to earn your reward.",
                "offer_url_easy": tracking_url,
                "payout": float(payout),
                "offer_type": item["survey_type"] or "Survey",
                "channel": "Wall",
                "payoutType": "flat",
                "amount": float(payout),
                "image_url": "",
                "countries": item["country"] or "All",
                "devices": item["device"] or "All",
                "preview_url": "",
                "events": [],
                "loi": item["loi"],
                "ir": (
                    float(item["incidence_rate"])
                    if item["incidence_rate"] is not None
                    else None
                ),
            }
        )
    return _no_store(
        JsonResponse(
            {
                "message": "success",
                "type": 1,
                "code": 200,
                "data": {
                    "query": {
                        "pubid": pubid,
                        "appid": placement.app_id,
                        "country": country.title() if country == "ALL" else country,
                        "platform": platform,
                    },
                    "response": {
                        "currency_name": placement.currency_name,
                        "offers": response_offers,
                    },
                },
            }
        )
    )


@require_GET
def offer_click_tracking(request):
    app_id = str(request.GET.get("app_id") or "").strip()
    placement_uuid = _app_uuid_from_id(app_id)
    if not placement_uuid:
        return _error(request, "Invalid placement", "A valid app_id is required.")
    placement = get_object_or_404(
        PublisherPlacement.objects.select_related("publisher"),
        public_id=placement_uuid,
        status=PublisherPlacement.Status.ACTIVE,
        publisher__is_active=True,
    )
    external_user_id = str(
        request.GET.get("uid") or request.GET.get("SID") or ""
    ).strip()
    if (
        not USER_ID_RE.fullmatch(external_user_id)
        or "{" in external_user_id
        or "}" in external_user_id
    ):
        return _error(request, "Invalid respondent", "A valid uid is required.")
    survey = get_object_or_404(Survey, local_id=request.GET.get("offer_id"))
    visit = create_api_visit(
        placement.publisher,
        external_user_id=external_user_id,
        request=request,
        placement=placement,
        external_campaign_id=request.GET.get("sid", ""),
        affiliate_sub_id=request.GET.get("sid2", ""),
        affiliate_sub_id_3=request.GET.get("sid3", ""),
        affiliate_sub_id_4=request.GET.get("sid4", ""),
        affiliate_sub_id_5=request.GET.get("sid5", ""),
        idfa=request.GET.get("idfa", ""),
        gaid=request.GET.get("gaid", ""),
    )
    try:
        click, _ = create_offer_click(visit=visit, survey=survey, request=request)
    except ValueError as exc:
        return _error(request, "Offer unavailable", str(exc), status=409)
    return _no_store(
        HttpResponseRedirect(f"{reverse('survey-start')}?rid={click.attempt.rid}")
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


def _publisher_portal_or_response(request):
    supplier_account = _supplier_account(request)
    if supplier_account and (
        supplier_account.status != PublisherPortalAccount.Status.APPROVED
        or not supplier_account.publisher.is_active
    ):
        return None, _no_store(
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
        return None, _error(
            request,
            "Publisher access required",
            "Sign in with an approved supplier account to continue.",
            status=403,
        )
    return publisher, None


def _supplier_portal_context(publisher, active_page):
    return {
        "portal_publisher": publisher,
        "portal_wallet": wallet_summary(publisher),
        "supplier_portal_enabled": True,
        "supplier_active_page": active_page,
    }


def _placement_embed_details(request, placement):
    base_url = request.build_absolute_uri(
        reverse("offerwall:placement-app-embed", kwargs={"app_id": placement.app_id})
    )
    iframe_url = f"{base_url}?SID={{SID}}"
    iframe_script_url = request.build_absolute_uri(f"{static('offerwall/embed.js')}?v=1")
    iframe_id = f"rmw-offerwall-{placement.public_id.hex[:10]}"
    api_url = request.build_absolute_uri(reverse("offerwall:offers-api"))
    placement.embed_preview_url = base_url
    placement.direct_url = iframe_url
    placement.api_url = api_url
    placement.api_example_url = (
        f"{api_url}?key={{API_KEY}}&pubid={placement.publisher.publisher_code}"
        f"&app_id={placement.app_id}&platform=All&country=All&type=live_surveys"
    )
    placement.iframe_code = (
        f'<iframe id="{iframe_id}" class="rmw-offerwall-frame" '
        f'data-rmw-app-id="{placement.app_id}" src="{iframe_url}" '
        'title="RM Wins Offer Wall" width="100%" height="800" loading="lazy" '
        'referrerpolicy="strict-origin" '
        'style="display:block;width:100%;min-height:600px;border:0;"></iframe>\n'
        f'<script src="{iframe_script_url}" defer></script>\n'
        f'<noscript><a href="{iframe_url}" target="_blank" rel="noopener">'
        'Open RM Wins Offer Wall</a></noscript>'
    )
    return placement


def _publisher_placements_response(request, publisher, *, form):
    money_field = DecimalField(max_digits=14, decimal_places=2)
    placement_queryset = (
        publisher.placements.exclude(
            status=PublisherPlacement.Status.ARCHIVED
        ).annotate(
            visit_count=Count("visits", distinct=True),
            click_count=Count("visits__clicks", distinct=True),
            complete_count=Count(
                "visits__clicks",
                filter=Q(
                    visits__clicks__status=SurveyAttempt.Status.COMPLETED,
                    visits__clicks__is_verified=True,
                ),
                distinct=True,
            ),
            credit_revenue=Coalesce(
                Sum(
                    "visits__clicks__ledger_entries__amount",
                    filter=Q(
                        visits__clicks__ledger_entries__entry_type=RewardLedgerEntry.EntryType.CREDIT
                    ),
                ),
                Value(Decimal("0.00"), output_field=money_field),
                output_field=money_field,
            ),
            reversal_revenue=Coalesce(
                Sum(
                    "visits__clicks__ledger_entries__amount",
                    filter=Q(
                        visits__clicks__ledger_entries__entry_type=RewardLedgerEntry.EntryType.REVERSAL
                    ),
                ),
                Value(Decimal("0.00"), output_field=money_field),
                output_field=money_field,
            ),
        ).order_by("-created_at")
    )
    paginator = Paginator(placement_queryset, 10)
    placements = paginator.get_page(request.GET.get("page"))
    for placement in placements:
        placement.total_revenue = placement.credit_revenue - placement.reversal_revenue
        website = urlparse(placement.website_url)
        placement.favicon_url = (
            f"{website.scheme}://{website.netloc}/favicon.ico"
            if website.scheme and website.netloc
            else ""
        )
    context = _supplier_portal_context(publisher, "placements")
    context.update(
        {
            "form": form,
            "placements": placements,
            "placement_total": paginator.count,
        }
    )
    return _no_store(render(request, "offerwall/publisher_placements.html", context))


@require_http_methods(["GET", "POST"])
def publisher_placements(request):
    publisher, denied = _publisher_portal_or_response(request)
    if denied:
        return denied
    form = PublisherPlacementCreateForm(
        request.POST or None,
        publisher=publisher,
    )
    if request.method == "POST" and form.is_valid():
        placement = form.save()
        messages.success(
            request,
            f"Placement “{placement.name}” created. Open Settings to complete its integration.",
        )
        return _no_store(
            HttpResponseRedirect(reverse("offerwall:publisher-placements"))
        )
    return _publisher_placements_response(request, publisher, form=form)


@require_http_methods(["GET", "POST"])
def publisher_placement_edit(request, placement_id):
    publisher, denied = _publisher_portal_or_response(request)
    if denied:
        return denied
    placement = get_object_or_404(
        PublisherPlacement,
        publisher=publisher,
        public_id=placement_id,
    )
    form_type = str(request.POST.get("form_type") or "").strip()
    form_classes = {
        "general": PlacementGeneralForm,
        "currency": PlacementCurrencyForm,
        "postback": PlacementPostbackForm,
        "design": PlacementDesignForm,
    }
    bound_forms = {}
    if request.method == "POST" and form_type in form_classes:
        form_class = form_classes[form_type]
        form = form_class(
            request.POST,
            request.FILES if form_type == "design" else None,
            instance=placement,
        )
        bound_forms[form_type] = form
        if form.is_valid():
            form.save()
            messages.success(request, f"{form_type.title()} settings saved.")
            destination = reverse(
                "offerwall:publisher-placement-edit",
                kwargs={"placement_id": placement.public_id},
            )
            return _no_store(HttpResponseRedirect(f"{destination}#{form_type}"))
    elif request.method == "POST":
        raise Http404
    return _publisher_placement_settings_response(
        request,
        publisher,
        placement,
        bound_forms=bound_forms,
        active_tab=form_type or "general",
    )


def _publisher_placement_settings_response(
    request,
    publisher,
    placement,
    *,
    bound_forms=None,
    event_form=None,
    active_tab="general",
):
    bound_forms = bound_forms or {}
    _placement_embed_details(request, placement)
    placement.postback_secret_plain = decrypt_placement_postback_secret(placement)
    placement.api_key_plain = decrypt_api_key(publisher)
    if placement.currency_icon:
        placement.currency_icon_public_url = reverse(
            "offerwall:placement-brand-asset",
            kwargs={"placement_id": placement.public_id, "kind": "currency-icon"},
        )
    if placement.header_logo:
        placement.header_logo_public_url = reverse(
            "offerwall:placement-brand-asset",
            kwargs={"placement_id": placement.public_id, "kind": "header-logo"},
        )
    context = _supplier_portal_context(publisher, "placements")
    context.update(
        {
            "placement": placement,
            "general_form": bound_forms.get("general")
            or PlacementGeneralForm(instance=placement),
            "currency_form": bound_forms.get("currency")
            or PlacementCurrencyForm(instance=placement),
            "postback_form": bound_forms.get("postback")
            or PlacementPostbackForm(instance=placement),
            "design_form": bound_forms.get("design")
            or PlacementDesignForm(instance=placement),
            "event_postbacks": placement.event_postbacks.select_related("survey"),
            "active_settings_tab": active_tab,
            "postback_source_ip": getattr(
                settings, "OFFERWALL_POSTBACK_SOURCE_IP", "Not fixed"
            ),
        }
    )
    return _no_store(
        render(request, "offerwall/publisher_placement_settings.html", context)
    )


@require_http_methods(["GET", "POST"])
def publisher_placement_event_postback_add(request, placement_id):
    publisher, denied = _publisher_portal_or_response(request)
    if denied:
        return denied
    placement = get_object_or_404(
        PublisherPlacement, publisher=publisher, public_id=placement_id
    )
    form = PlacementEventPostbackForm(
        request.POST or None,
        placement=placement,
    )
    if request.method == "POST" and form.is_valid():
        placement.postback_email_opt_out = bool(
            request.POST.get("postback_email_opt_out")
        )
        placement.save(update_fields=["postback_email_opt_out", "updated_at"])
        event_postback = form.save(commit=False)
        event_postback.placement = placement
        event_postback.survey = form.cleaned_data["survey_id"]
        event_postback.event_name = str(request.POST.get("event_name") or "").strip()[:120]
        event_postback.save()
        messages.success(request, "Specific event postback added.")
        destination = reverse(
            "offerwall:publisher-placement-edit",
            kwargs={"placement_id": placement.public_id},
        )
        return _no_store(HttpResponseRedirect(f"{destination}#postback"))
    context = _supplier_portal_context(publisher, "placements")
    context.update(
        {
            "placement": placement,
            "event_form": form,
            "survey_options": Survey.objects.filter(status=Survey.Status.LIVE)
            .only("local_id", "name")
            .order_by("name", "local_id"),
            "postback_source_ip": getattr(
                settings, "OFFERWALL_POSTBACK_SOURCE_IP", "Not fixed"
            ),
            "postback_secret": decrypt_placement_postback_secret(placement),
        }
    )
    return _no_store(
        render(request, "offerwall/publisher_placement_postback_create.html", context)
    )


@require_POST
def publisher_placement_event_postback_action(request, placement_id, postback_id):
    publisher, denied = _publisher_portal_or_response(request)
    if denied:
        return denied
    rule = get_object_or_404(
        PlacementEventPostback.objects.select_related("placement"),
        public_id=postback_id,
        placement__public_id=placement_id,
        placement__publisher=publisher,
    )
    action = str(request.POST.get("action") or "").strip()
    if action == "toggle":
        rule.is_active = not rule.is_active
        rule.save(update_fields=["is_active", "updated_at"])
        messages.success(request, "Specific event postback status updated.")
    elif action == "delete":
        rule.delete()
        messages.success(request, "Specific event postback deleted.")
    else:
        raise Http404
    destination = reverse(
        "offerwall:publisher-placement-edit",
        kwargs={"placement_id": placement_id},
    )
    return _no_store(HttpResponseRedirect(f"{destination}#postback"))


@require_POST
def publisher_placement_postback_test(request, placement_id):
    publisher, denied = _publisher_portal_or_response(request)
    if denied:
        return denied
    placement = get_object_or_404(
        PublisherPlacement, publisher=publisher, public_id=placement_id
    )
    if not placement.postback_enabled or not placement.postback_url:
        messages.error(request, "Enable postbacks and save a URL before testing.")
    else:
        payload = {
            "app_id": placement.app_id,
            "user_id": "test-user",
            "offer_id": "test-offer",
            "status": "1",
            "reward_amount": "1.00",
            "payout_amount": "1.00",
            "transaction_id": f"test-{secrets.token_hex(8)}",
            "event_id": "test-event",
            "event": "test",
        }
        signing_secret = decrypt_placement_postback_secret(placement)
        try:
            callback_url = _render_postback_url(placement.postback_url, payload)
            transaction_signature = hmac.new(
                signing_secret.encode("utf-8"),
                payload["transaction_id"].encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            callback_url = _validated_callback_url(
                callback_url.replace("{SIG}", transaction_signature)
            )
            response = requests.get(
                callback_url,
                headers={"User-Agent": "RMWins-Offerwall-Test/1.0"},
                timeout=settings.OFFERWALL_POSTBACK_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
            if 200 <= response.status_code < 300 and response.text.strip() == "1":
                messages.success(request, "Postback connection successful. Response body: 1")
            else:
                messages.error(
                    request,
                    f'Postback must return body "1" (HTTP {response.status_code}).',
                )
        except Exception as exc:
            messages.error(request, f"Postback test failed: {str(exc)[:180]}")
    destination = reverse(
        "offerwall:publisher-placement-edit",
        kwargs={"placement_id": placement.public_id},
    )
    return _no_store(HttpResponseRedirect(f"{destination}#postback"))


@require_GET
def placement_brand_asset(request, placement_id, kind):
    placement = get_object_or_404(
        PublisherPlacement.objects.select_related("publisher"),
        public_id=placement_id,
        publisher__is_active=True,
    )
    field = {
        "currency-icon": placement.currency_icon,
        "header-logo": placement.header_logo,
    }.get(kind)
    if not field:
        raise Http404
    content_type = mimetypes.guess_type(field.name)[0] or "application/octet-stream"
    try:
        response = FileResponse(field.open("rb"), content_type=content_type)
    except (FileNotFoundError, OSError):
        raise Http404
    response["Cache-Control"] = "public, max-age=3600"
    response["Content-Security-Policy"] = "default-src 'none'"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@require_POST
def publisher_placement_action(request, placement_id):
    publisher, denied = _publisher_portal_or_response(request)
    if denied:
        return denied
    placement = get_object_or_404(
        PublisherPlacement,
        publisher=publisher,
        public_id=placement_id,
    )
    action = str(request.POST.get("action") or "").strip()
    if action == "delete":
        placement_name = placement.website_name
        placement.delete()
        messages.success(request, f"Placement “{placement_name}” deleted.")
    elif action == "rotate-postback-secret":
        placement.set_postback_secret(generate_signing_secret())
        placement.save(
            update_fields=[
                "encrypted_postback_secret",
                "postback_secret_last_four",
                "postback_secret_changed_at",
                "updated_at",
            ]
        )
        messages.success(request, "Postback secret reset successfully.")
    elif action == "rotate-api-key":
        raw_key = publisher.rotate_api_key()
        publisher.save(
            update_fields=[
                "api_key_hash",
                "encrypted_api_key",
                "api_key_prefix",
                "api_key_last_four",
                "api_key_changed_at",
                "api_key_last_used_at",
                "updated_at",
            ]
        )
        messages.success(request, "A new API key was generated.")
    else:
        raise Http404
    destination = reverse("offerwall:publisher-placements")
    if action in {"rotate-postback-secret", "rotate-api-key"}:
        destination = reverse(
            "offerwall:publisher-placement-edit",
            kwargs={"placement_id": placement.public_id},
        )
        destination = f"{destination}#{'postback' if action == 'rotate-postback-secret' else 'integrations'}"
    return _no_store(HttpResponseRedirect(destination))


SUPPLIER_SECTION_COPY = {
    "respondents": (
        "Respondents",
        "Respondent activity, unique users and engagement details will live here.",
    ),
    "survey-results": (
        "Survey results",
        "Review respondent journeys, verified outcomes, earnings and postback delivery.",
    ),
    "general-details": (
        "General details",
        "Company, integration and notification settings will be managed here.",
    ),
    "reports": (
        "Reports",
        "Downloadable traffic, conversion and earnings reports are coming next.",
    ),
}


SURVEY_RESULT_STATUS_FILTERS = {
    "in_progress": [
        SurveyAttempt.Status.INITIATED,
        SurveyAttempt.Status.REDIRECTED,
    ],
    "completed": [SurveyAttempt.Status.COMPLETED],
    "terminated": [SurveyAttempt.Status.TERMINATED],
    "over_quota": [SurveyAttempt.Status.OVER_QUOTA],
    "quality_terminated": [SurveyAttempt.Status.QUALITY_TERMINATED],
}


def _survey_result_filters(request, publisher):
    today = timezone.localdate()
    end_date = parse_date(str(request.GET.get("end") or "")) or today
    start_date = (
        parse_date(str(request.GET.get("start") or ""))
        or end_date - timedelta(days=29)
    )
    if start_date > end_date:
        start_date, end_date = end_date, start_date

    start_at = datetime.combine(start_date, time.min)
    end_at = datetime.combine(end_date + timedelta(days=1), time.min)
    if settings.USE_TZ:
        current_zone = timezone.get_current_timezone()
        start_at = timezone.make_aware(start_at, current_zone)
        end_at = timezone.make_aware(end_at, current_zone)

    search = str(request.GET.get("q") or "").strip()[:160]
    status_filter = str(request.GET.get("status") or "all").strip()
    if status_filter not in {"all", *SURVEY_RESULT_STATUS_FILTERS}:
        status_filter = "all"
    placement_filter = str(request.GET.get("placement") or "all").strip()
    if placement_filter != "all":
        try:
            placement_filter = str(uuid.UUID(placement_filter))
        except (TypeError, ValueError):
            placement_filter = "all"

    queryset = publisher.offer_clicks.filter(
        created_at__gte=start_at,
        created_at__lt=end_at,
    )
    if search:
        queryset = queryset.filter(
            Q(external_user_id__icontains=search)
            | Q(survey__local_id__icontains=search)
            | Q(survey__name__icontains=search)
            | Q(attempt__rid__icontains=search)
            | Q(attempt__pid__icontains=search)
            | Q(visit__external_campaign_id__icontains=search)
        )
    if status_filter != "all":
        queryset = queryset.filter(
            status__in=SURVEY_RESULT_STATUS_FILTERS[status_filter]
        )
    if placement_filter != "all":
        queryset = queryset.filter(visit__placement__public_id=placement_filter)

    filters = {
        "q": search,
        "status": status_filter,
        "placement": placement_filter,
        "start": start_date.isoformat(),
        "end": end_date.isoformat(),
    }
    return queryset.order_by("-created_at"), filters


def _survey_result_queryset(queryset):
    money_field = DecimalField(max_digits=14, decimal_places=2)
    return (
        queryset.select_related(
            "survey",
            "attempt",
            "visit",
            "visit__placement",
        )
        .prefetch_related(
            Prefetch(
                "postback_deliveries",
                queryset=PostbackDelivery.objects.order_by("-created_at"),
                to_attr="report_postbacks",
            ),
            Prefetch(
                "ledger_entries",
                queryset=RewardLedgerEntry.objects.order_by("-created_at"),
                to_attr="report_ledger_entries",
            ),
        )
        .annotate(
            report_credit=Coalesce(
                Sum(
                    "ledger_entries__amount",
                    filter=Q(
                        ledger_entries__entry_type=RewardLedgerEntry.EntryType.CREDIT
                    ),
                ),
                Value(Decimal("0.00"), output_field=money_field),
                output_field=money_field,
            ),
            report_reversal=Coalesce(
                Sum(
                    "ledger_entries__amount",
                    filter=Q(
                        ledger_entries__entry_type=RewardLedgerEntry.EntryType.REVERSAL
                    ),
                ),
                Value(Decimal("0.00"), output_field=money_field),
                output_field=money_field,
            ),
        )
    )


def _decorate_survey_result(click):
    click.report_outcome = provider_outcome(click.attempt)
    click.report_postback = click.report_postbacks[0] if click.report_postbacks else None
    click.report_reward = click.report_credit - click.report_reversal
    click.report_transaction_id = (
        str(click.report_ledger_entries[0].public_id)
        if click.report_ledger_entries
        else str(click.public_id)
    )
    return click


def _safe_csv_cell(value):
    value = str(value if value is not None else "")
    return f"'{value}" if value.startswith(("=", "+", "-", "@")) else value


class _CsvEcho:
    def write(self, value):
        return value


def _survey_results_csv(queryset, publisher, filters):
    writer = csv.writer(_CsvEcho())

    def rows():
        yield writer.writerow(
            [
                "Date",
                "Respondent ID",
                "Placement",
                "App ID",
                "Survey ID",
                "Survey",
                "Status",
                "Verified",
                "Reward",
                "Currency",
                "Term reason",
                "Term category",
                "Transaction ID",
                "Postback status",
                "Campaign ID",
                "Affiliate sub",
                "Country",
                "Device",
            ]
        )
        for click in _survey_result_queryset(queryset).iterator(chunk_size=500):
            _decorate_survey_result(click)
            placement = click.visit.placement
            postback = click.report_postback
            values = [
                timezone.localtime(click.created_at).isoformat(),
                click.external_user_id,
                placement.name if placement else "Direct wall",
                placement.app_id if placement else "",
                click.survey.local_id,
                click.survey.name or f"Survey {click.survey.local_id}",
                click.attempt.get_status_display(),
                "Yes" if click.is_verified else "No",
                f"{click.report_reward:.2f}",
                publisher.currency,
                click.report_outcome.get("reason", ""),
                click.report_outcome.get("category", ""),
                click.report_transaction_id,
                postback.get_status_display() if postback else "Not generated",
                click.visit.external_campaign_id,
                click.visit.affiliate_sub_id,
                click.visit.country_code,
                click.visit.device,
            ]
            yield writer.writerow([_safe_csv_cell(value) for value in values])

    filename = f"rmwins-survey-results-{filters['start']}-to-{filters['end']}.csv"
    response = StreamingHttpResponse(rows(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return _no_store(response)


def _publisher_survey_results_response(request, publisher):
    filtered_clicks, filters = _survey_result_filters(request, publisher)
    if str(request.GET.get("export") or "").strip().lower() == "csv":
        return _survey_results_csv(filtered_clicks, publisher, filters)

    summary = filtered_clicks.aggregate(
        total=Count("id"),
        completed=Count(
            "id",
            filter=Q(
                status=SurveyAttempt.Status.COMPLETED,
                is_verified=True,
            ),
        ),
        terminated=Count(
            "id", filter=Q(status=SurveyAttempt.Status.TERMINATED)
        ),
        over_quota=Count(
            "id", filter=Q(status=SurveyAttempt.Status.OVER_QUOTA)
        ),
        quality_terminated=Count(
            "id", filter=Q(status=SurveyAttempt.Status.QUALITY_TERMINATED)
        ),
    )
    ledger = RewardLedgerEntry.objects.filter(
        publisher=publisher,
        click_id__in=filtered_clicks.values("pk").order_by(),
    ).aggregate(
        credits=Coalesce(
            Sum(
                "amount",
                filter=Q(entry_type=RewardLedgerEntry.EntryType.CREDIT),
            ),
            Value(Decimal("0.00")),
        ),
        reversals=Coalesce(
            Sum(
                "amount",
                filter=Q(entry_type=RewardLedgerEntry.EntryType.REVERSAL),
            ),
            Value(Decimal("0.00")),
        ),
    )
    summary["earnings"] = ledger["credits"] - ledger["reversals"]
    summary["conversion_rate"] = (
        (summary["completed"] / summary["total"] * 100) if summary["total"] else 0
    )

    result_page = Paginator(_survey_result_queryset(filtered_clicks), 40).get_page(
        request.GET.get("page")
    )
    for click in result_page:
        _decorate_survey_result(click)

    context = _supplier_portal_context(publisher, "survey-results")
    context.update(
        {
            "survey_results": result_page,
            "survey_result_summary": summary,
            "survey_result_filters": filters,
            "survey_result_query": urlencode(filters),
            "survey_result_placements": publisher.placements.order_by(
                "website_name", "name"
            ),
            "survey_result_timezone": timezone.get_current_timezone_name(),
        }
    )
    return _no_store(
        render(request, "offerwall/publisher_survey_results.html", context)
    )


def _publisher_respondents_response(request, publisher):
    queryset = publisher.respondents.select_related(
        "publisher", "first_placement", "last_placement"
    ).annotate(
        visit_count=Count("visits", distinct=True),
        click_count=Count("visits__clicks", distinct=True),
        completed_count=Count(
            "visits__clicks",
            filter=Q(
                visits__clicks__status=SurveyAttempt.Status.COMPLETED,
                visits__clicks__is_verified=True,
            ),
            distinct=True,
        ),
        last_activity_at=Max("visits__last_seen_at"),
    )
    search = str(request.GET.get("q") or "").strip()
    if search:
        if "@" in search:
            queryset = queryset.filter(email_hash=respondent_email_hash(search))
        else:
            queryset = queryset.filter(external_user_id__icontains=search)
    status_filter = str(request.GET.get("status") or "all").strip()
    if status_filter == "verified":
        queryset = queryset.filter(is_email_verified=True, is_banned=False)
    elif status_filter == "unverified":
        queryset = queryset.filter(is_email_verified=False, is_banned=False)
    elif status_filter == "banned":
        queryset = queryset.filter(is_banned=True)

    summary = publisher.respondents.aggregate(
        total=Count("id"),
        verified=Count("id", filter=Q(is_email_verified=True, is_banned=False)),
        unverified=Count("id", filter=Q(is_email_verified=False, is_banned=False)),
        banned=Count("id", filter=Q(is_banned=True)),
    )
    respondents = Paginator(queryset.order_by("-last_seen_at"), 25).get_page(
        request.GET.get("page")
    )
    context = _supplier_portal_context(publisher, "respondents")
    context.update(
        {
            "respondents": respondents,
            "respondent_summary": summary,
            "respondent_search": search,
            "respondent_status": status_filter,
        }
    )
    return _no_store(render(request, "offerwall/publisher_respondents.html", context))


@require_GET
def publisher_section(request, section):
    if section not in SUPPLIER_SECTION_COPY:
        raise Http404
    publisher, denied = _publisher_portal_or_response(request)
    if denied:
        return denied
    if section == "respondents":
        return _publisher_respondents_response(request, publisher)
    if section == "survey-results":
        return _publisher_survey_results_response(request, publisher)
    title, description = SUPPLIER_SECTION_COPY[section]
    context = _supplier_portal_context(publisher, section)
    context.update({"section_title": title, "section_description": description})
    return _no_store(render(request, "offerwall/publisher_placeholder.html", context))


@require_POST
def publisher_respondent_action(request, respondent_id):
    publisher, denied = _publisher_portal_or_response(request)
    if denied:
        return denied
    respondent = get_object_or_404(
        RespondentProfile,
        public_id=respondent_id,
        publisher=publisher,
    )
    action = str(request.POST.get("action") or "").strip()
    if action == "ban":
        respondent.is_banned = True
        respondent.banned_at = timezone.now()
        respondent.ban_reason = str(request.POST.get("reason") or "").strip()[:255]
        respondent.save(
            update_fields=["is_banned", "banned_at", "ban_reason", "updated_at"]
        )
        messages.success(request, f"{respondent.external_user_id} was banned.")
    elif action == "unban":
        respondent.is_banned = False
        respondent.banned_at = None
        respondent.ban_reason = ""
        respondent.save(
            update_fields=["is_banned", "banned_at", "ban_reason", "updated_at"]
        )
        messages.success(request, f"{respondent.external_user_id} was unbanned.")
    else:
        messages.error(request, "Unknown respondent action.")
    return _no_store(HttpResponseRedirect(reverse("offerwall:publisher-section", args=["respondents"])))


def _placement_embed_response(request, placement):
    if _rate_limited(
        request,
        "placement-entry",
        settings.OFFERWALL_ENTRY_RATE_LIMIT_PER_MINUTE,
    ):
        response = _error(
            request,
            "Too many requests",
            "Please wait a minute and try again.",
            status=429,
        )
        return _apply_placement_frame_policy(response, placement)
    if not _placement_referrer_allowed(placement, request):
        response = _error(
            request,
            "Domain not allowed",
            "This placement is not configured for the website embedding it.",
            status=403,
        )
        return _apply_placement_frame_policy(response, placement)
    external_user_id = str(
        request.GET.get("SID")
        or request.GET.get(placement.respondent_id_parameter)
        or ""
    ).strip()
    if (
        not external_user_id
        or "{" in external_user_id
        or "}" in external_user_id
    ):
        response = render(
            request,
            "offerwall/placement_embed.html",
            {"placement": placement},
        )
        return _no_store(_apply_placement_frame_policy(response, placement))
    if not USER_ID_RE.fullmatch(external_user_id):
        response = _error(
            request,
            "Invalid respondent ID",
            "Use a valid respondent identifier.",
        )
        return _apply_placement_frame_policy(response, placement)

    request._offerwall_parent_origin = _external_referrer_origin(request)
    profile = RespondentProfile.objects.filter(
        publisher=placement.publisher,
        external_user_id=external_user_id,
    ).first()
    if profile and profile.is_banned:
        return _respondent_gate_response(
            request,
            placement,
            external_user_id,
            mode="banned",
            form=None,
            profile=profile,
            status=403,
        )

    if request.method == "POST":
        if not _respondent_state_is_valid(
            request,
            request.POST.get("respondent_state"),
            placement,
            external_user_id,
        ):
            response = _error(
                request,
                "Invalid onboarding request",
                "Reload the offerwall and try again.",
                status=403,
            )
            return _apply_placement_frame_policy(response, placement)

        action = str(request.POST.get("action") or "").strip()
        if action == "register" and not (profile and profile.is_email_verified):
            form = RespondentOnboardingForm(
                request.POST,
                publisher=placement.publisher,
                profile=profile,
            )
            if form.is_valid():
                try:
                    with transaction.atomic():
                        if profile is None:
                            profile = RespondentProfile(
                                publisher=placement.publisher,
                                external_user_id=external_user_id,
                                first_placement=placement,
                            )
                        profile.set_identity(
                            full_name=form.cleaned_data["full_name"],
                            email=form.cleaned_data["email"],
                        )
                        profile.age = form.cleaned_data["age"]
                        profile.gender = form.cleaned_data["gender"]
                        profile.last_placement = placement
                        profile.last_seen_at = timezone.now()
                        profile.is_email_verified = False
                        profile.email_verified_at = None
                        profile.save()
                except IntegrityError:
                    form.add_error(
                        "email",
                        "This email is already linked to another respondent ID.",
                    )
                else:
                    try:
                        issue_respondent_verification(profile, force=True)
                    except Exception:
                        logger.exception(
                            "Could not send respondent verification email for profile %s",
                            profile.public_id,
                        )
                        return _respondent_gate_response(
                            request,
                            placement,
                            external_user_id,
                            mode="verify",
                            form=RespondentVerificationForm(),
                            profile=profile,
                            notice="We could not send the email. Check the address and request a new code.",
                            status=503,
                        )
                    return _respondent_gate_response(
                        request,
                        placement,
                        external_user_id,
                        mode="verify",
                        form=RespondentVerificationForm(),
                        profile=profile,
                        notice="A 6-digit verification code was sent to your email.",
                    )
            if form.errors:
                return _respondent_gate_response(
                    request,
                    placement,
                    external_user_id,
                    mode="register",
                    form=form,
                    profile=profile,
                )

        elif action == "verify" and profile:
            form = RespondentVerificationForm(request.POST)
            if form.is_valid():
                try:
                    profile = verify_respondent_code(profile, form.cleaned_data["code"])
                except ValidationError as exc:
                    form.add_error("code", exc)
                else:
                    profile.last_placement = placement
                    profile.last_seen_at = timezone.now()
                    profile.save(update_fields=["last_placement", "last_seen_at", "updated_at"])
            if form.errors:
                return _respondent_gate_response(
                    request,
                    placement,
                    external_user_id,
                    mode="verify",
                    form=form,
                    profile=profile,
                )

        elif action == "resend" and profile and not profile.is_email_verified:
            notice = "A new verification code was sent to your email."
            status = 200
            try:
                issue_respondent_verification(profile)
            except ValidationError as exc:
                notice = " ".join(exc.messages)
                status = 429
            except Exception:
                logger.exception(
                    "Could not resend respondent verification email for profile %s",
                    profile.public_id,
                )
                notice = "We could not send the email right now. Please try again shortly."
                status = 503
            return _respondent_gate_response(
                request,
                placement,
                external_user_id,
                mode="verify",
                form=RespondentVerificationForm(),
                profile=profile,
                notice=notice,
                status=status,
            )

    if profile is None or (
        not profile.is_email_verified and request.GET.get("edit") == "1"
    ):
        initial = {}
        if profile:
            initial = {
                "full_name": profile.full_name,
                "email": profile.email,
                "age": profile.age,
                "gender": profile.gender,
                "consent": True,
            }
        return _respondent_gate_response(
            request,
            placement,
            external_user_id,
            mode="register",
            form=RespondentOnboardingForm(
                publisher=placement.publisher,
                profile=profile,
                initial=initial,
            ),
            profile=profile,
        )

    if not profile.is_email_verified:
        return _respondent_gate_response(
            request,
            placement,
            external_user_id,
            mode="verify",
            form=RespondentVerificationForm(),
            profile=profile,
        )

    profile.last_placement = placement
    profile.last_seen_at = timezone.now()
    profile.save(update_fields=["last_placement", "last_seen_at", "updated_at"])
    visit = create_api_visit(
        placement.publisher,
        external_user_id=external_user_id,
        request=request,
        placement=placement,
        external_campaign_id=request.GET.get(placement.campaign_id_parameter, ""),
        affiliate_sub_id=request.GET.get(placement.affiliate_sub_parameter, ""),
        affiliate_sub_id_3=request.GET.get("sid3", ""),
        affiliate_sub_id_4=request.GET.get("sid4", ""),
        affiliate_sub_id_5=request.GET.get("sid5", ""),
        idfa=request.GET.get("idfa", ""),
        gaid=request.GET.get("gaid", ""),
        respondent=profile,
    )
    return _render_wall_response(request, visit)


@xframe_options_exempt
@csrf_exempt
@require_http_methods(["GET", "POST"])
def placement_app_embed(request, app_id):
    placement_uuid = _app_uuid_from_id(app_id)
    if not placement_uuid:
        return _error(request, "Invalid placement", "Use a valid RM Wins App ID.", status=404)
    placement = get_object_or_404(
        PublisherPlacement.objects.select_related("publisher"),
        public_id=placement_uuid,
        status=PublisherPlacement.Status.ACTIVE,
        publisher__is_active=True,
    )
    return _placement_embed_response(request, placement)


@xframe_options_exempt
@csrf_exempt
@require_http_methods(["GET", "POST"])
def placement_embed(request, placement_id):
    """Legacy UUID embed route retained for existing publisher snippets."""
    placement = get_object_or_404(
        PublisherPlacement.objects.select_related("publisher"),
        public_id=placement_id,
        status=PublisherPlacement.Status.ACTIVE,
        publisher__is_active=True,
    )
    return _placement_embed_response(request, placement)


@require_GET
def publisher_dashboard(request):
    publisher, denied = _publisher_portal_or_response(request)
    if denied:
        return denied
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
            **_supplier_portal_context(publisher, "dashboard"),
            "wallet": wallet,
            "stats": stats,
            "placement_count": publisher.placements.count(),
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
