"""Authoritative wallet accounting and calendar-month supplier billing."""

from datetime import date, datetime, time, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q, Sum
from django.utils import timezone

from .models import Publisher, PublisherPayoutRequest, RewardLedgerEntry


MONEY_QUANTUM = Decimal("0.01")
RESERVED_PAYOUT_STATUSES = {
    PublisherPayoutRequest.Status.PENDING,
    PublisherPayoutRequest.Status.APPROVED,
    PublisherPayoutRequest.Status.PROCESSING,
}
FINAL_PAYOUT_STATUSES = {
    PublisherPayoutRequest.Status.PAID,
    PublisherPayoutRequest.Status.REJECTED,
    PublisherPayoutRequest.Status.CANCELED,
}
ALLOWED_PAYOUT_TRANSITIONS = {
    PublisherPayoutRequest.Status.PENDING: {
        PublisherPayoutRequest.Status.APPROVED,
        PublisherPayoutRequest.Status.REJECTED,
        PublisherPayoutRequest.Status.CANCELED,
    },
    PublisherPayoutRequest.Status.APPROVED: {
        PublisherPayoutRequest.Status.PROCESSING,
        PublisherPayoutRequest.Status.REJECTED,
        PublisherPayoutRequest.Status.CANCELED,
    },
    PublisherPayoutRequest.Status.PROCESSING: {
        PublisherPayoutRequest.Status.PAID,
        PublisherPayoutRequest.Status.REJECTED,
    },
}


def normalize_money(value) -> Decimal:
    try:
        amount = Decimal(str(value or "")).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValidationError("Enter a valid billing amount.") from exc
    if not amount.is_finite() or amount <= 0:
        raise ValidationError("Billing amount must be greater than zero.")
    return amount


def wallet_summary(publisher: Publisher) -> dict:
    ledger = publisher.reward_ledger.aggregate(
        credits=Sum(
            "amount",
            filter=Q(entry_type=RewardLedgerEntry.EntryType.CREDIT),
            default=Decimal("0.00"),
        ),
        reversals=Sum(
            "amount",
            filter=Q(entry_type=RewardLedgerEntry.EntryType.REVERSAL),
            default=Decimal("0.00"),
        ),
        pending=Sum(
            "amount",
            filter=Q(
                entry_type=RewardLedgerEntry.EntryType.CREDIT,
                status=RewardLedgerEntry.Status.PENDING,
            ),
            default=Decimal("0.00"),
        ),
        released=Sum(
            "amount",
            filter=Q(
                entry_type=RewardLedgerEntry.EntryType.CREDIT,
                status=RewardLedgerEntry.Status.AVAILABLE,
            ),
            default=Decimal("0.00"),
        ),
        voided=Sum(
            "amount",
            filter=Q(
                entry_type=RewardLedgerEntry.EntryType.CREDIT,
                status=RewardLedgerEntry.Status.VOIDED,
            ),
            default=Decimal("0.00"),
        ),
    )
    payouts = publisher.payout_requests.aggregate(
        reserved=Sum(
            "amount",
            filter=Q(status__in=RESERVED_PAYOUT_STATUSES),
            default=Decimal("0.00"),
        ),
        paid=Sum(
            "amount",
            filter=Q(status=PublisherPayoutRequest.Status.PAID),
            default=Decimal("0.00"),
        ),
    )
    credits = (ledger["credits"] or Decimal("0.00")).quantize(MONEY_QUANTUM)
    reversals = (ledger["reversals"] or Decimal("0.00")).quantize(MONEY_QUANTUM)
    pending = (ledger["pending"] or Decimal("0.00")).quantize(MONEY_QUANTUM)
    released = (ledger["released"] or Decimal("0.00")).quantize(MONEY_QUANTUM)
    voided = (ledger["voided"] or Decimal("0.00")).quantize(MONEY_QUANTUM)
    reserved = (payouts["reserved"] or Decimal("0.00")).quantize(MONEY_QUANTUM)
    paid = (payouts["paid"] or Decimal("0.00")).quantize(MONEY_QUANTUM)
    net_earnings = released
    available = max(Decimal("0.00"), released - reserved - paid)
    exposure = max(Decimal("0.00"), reserved + paid - released)
    today = timezone.localdate()
    next_billing_date = (today.replace(day=28) + timedelta(days=4)).replace(day=1)
    return {
        "credits": credits,
        "reversals": reversals,
        "net_earnings": net_earnings,
        "pending": pending,
        "released": released,
        "voided": voided,
        "reserved": reserved,
        "paid": paid,
        "available": available,
        "exposure": exposure,
        "currency": publisher.currency,
        "minimum_payout": settings.OFFERWALL_MINIMUM_PAYOUT,
        "billing_cycle": "monthly",
        "next_billing_date": next_billing_date,
    }


def previous_billing_period(reference_date: date | None = None) -> tuple[date, date]:
    """Return the previous closed calendar month in the application timezone."""

    reference = reference_date or timezone.localdate()
    current_month = reference.replace(day=1)
    period_end = current_month - timedelta(days=1)
    return period_end.replace(day=1), period_end


def billable_balance(publisher: Publisher, *, period_end: date) -> Decimal:
    """Return rewards released by the period cutoff and not already billed."""

    cutoff = timezone.make_aware(
        datetime.combine(period_end + timedelta(days=1), time.min),
        timezone.get_current_timezone(),
    )
    released = publisher.reward_ledger.aggregate(
        value=Sum(
            "amount",
            filter=Q(
                entry_type=RewardLedgerEntry.EntryType.CREDIT,
                status=RewardLedgerEntry.Status.AVAILABLE,
                released_at__lt=cutoff,
            ),
            default=Decimal("0.00"),
        )
    )["value"] or Decimal("0.00")
    already_billed = publisher.payout_requests.aggregate(
        value=Sum(
            "amount",
            filter=Q(
                status__in=RESERVED_PAYOUT_STATUSES
                | {PublisherPayoutRequest.Status.PAID},
            )
            & (
                Q(billing_period_start__isnull=False, billing_period_end__lte=period_end)
                | Q(billing_period_start__isnull=True, requested_at__lt=cutoff)
            ),
            default=Decimal("0.00"),
        )
    )["value"] or Decimal("0.00")
    return max(
        Decimal("0.00"),
        (released - already_billed).quantize(MONEY_QUANTUM),
    )


def generate_monthly_billing(
    publisher: Publisher,
    *,
    reference_date: date | None = None,
) -> tuple[PublisherPayoutRequest | None, bool]:
    """Lock the complete unbilled balance into one idempotent monthly statement."""

    period_start, period_end = previous_billing_period(reference_date)
    try:
        with transaction.atomic():
            locked_publisher = Publisher.objects.select_for_update().get(pk=publisher.pk)
            existing = PublisherPayoutRequest.objects.filter(
                publisher=locked_publisher,
                currency=locked_publisher.currency,
                billing_period_start=period_start,
            ).first()
            if existing:
                return existing, False
            amount = billable_balance(
                locked_publisher,
                period_end=period_end,
            )
            if amount <= 0:
                return None, False
            statement = PublisherPayoutRequest.objects.create(
                publisher=locked_publisher,
                invoice_number=(
                    f"RMW-{period_start:%Y%m}-{int(locked_publisher.publisher_number):06d}"
                ),
                billing_period_start=period_start,
                billing_period_end=period_end,
                generated_automatically=True,
                amount=amount,
                currency=locked_publisher.currency,
                payout_method="Monthly settlement",
                publisher_note="System-generated from the unbilled available balance.",
                available_balance_snapshot=amount,
            )
            return statement, True
    except IntegrityError:
        return (
            PublisherPayoutRequest.objects.filter(
                publisher=publisher,
                currency=publisher.currency,
                billing_period_start=period_start,
            ).first(),
            False,
        )


def generate_due_monthly_billings(reference_date: date | None = None) -> dict:
    """Generate the previous month's statements for every supplier, safely repeatable."""

    created = 0
    skipped = 0
    invoice_ids = []
    for publisher in Publisher.objects.order_by("pk").iterator(chunk_size=200):
        statement, was_created = generate_monthly_billing(
            publisher,
            reference_date=reference_date,
        )
        if was_created and statement:
            created += 1
            invoice_ids.append(str(statement.public_id))
        else:
            skipped += 1
    period_start, period_end = previous_billing_period(reference_date)
    return {
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "created": created,
        "skipped": skipped,
        "invoice_ids": invoice_ids,
    }


def request_withdrawal(
    publisher: Publisher, *, amount, payout_method: str, publisher_note: str = ""
) -> PublisherPayoutRequest:
    raise ValidationError(
        "Manual withdrawals are disabled. Billing is generated automatically after each month closes."
    )


def transition_payout(
    payout: PublisherPayoutRequest,
    new_status: str,
    *,
    reviewer=None,
    payment_reference: str = "",
    admin_note: str = "",
) -> PublisherPayoutRequest:
    with transaction.atomic():
        locked = PublisherPayoutRequest.objects.select_for_update().get(pk=payout.pk)
        if new_status == locked.status:
            return locked
        if new_status not in ALLOWED_PAYOUT_TRANSITIONS.get(locked.status, set()):
            raise ValidationError(
                f"Billing statement cannot move from {locked.get_status_display()} to {new_status}."
            )
        reference = str(payment_reference or locked.payment_reference or "").strip()
        if new_status == PublisherPayoutRequest.Status.PAID and not reference:
            raise ValidationError("A payment reference is required before marking billing paid.")
        now = timezone.now()
        locked.status = new_status
        locked.reviewed_by = reviewer
        locked.reviewed_at = now
        locked.admin_note = str(admin_note or locked.admin_note or "").strip()[:500]
        locked.payment_reference = reference[:160]
        if new_status == PublisherPayoutRequest.Status.PAID:
            locked.paid_at = now
        locked.save(
            update_fields=[
                "status",
                "reviewed_by",
                "reviewed_at",
                "admin_note",
                "payment_reference",
                "paid_at",
                "updated_at",
            ]
        )
        return locked
