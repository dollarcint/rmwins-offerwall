"""Authoritative publisher wallet accounting and withdrawal state transitions."""

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
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
        raise ValidationError("Enter a valid withdrawal amount.") from exc
    if not amount.is_finite() or amount <= 0:
        raise ValidationError("Withdrawal amount must be greater than zero.")
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
    }
def request_withdrawal(
    publisher: Publisher, *, amount, payout_method: str, publisher_note: str = ""
) -> PublisherPayoutRequest:
    amount = normalize_money(amount)
    payout_method = str(payout_method or "").strip()
    if not 2 <= len(payout_method) <= 80:
        raise ValidationError("Select or enter a valid payout method.")
    if amount < settings.OFFERWALL_MINIMUM_PAYOUT:
        raise ValidationError(
            f"Minimum withdrawal is {publisher.currency} {settings.OFFERWALL_MINIMUM_PAYOUT:.2f}."
        )
    with transaction.atomic():
        locked_publisher = Publisher.objects.select_for_update().get(pk=publisher.pk)
        summary = wallet_summary(locked_publisher)
        if summary["exposure"] > 0:
            raise ValidationError(
                "Withdrawals are paused while a reversed-balance adjustment is outstanding."
            )
        if amount > summary["available"]:
            raise ValidationError("Withdrawal amount exceeds the available balance.")
        return PublisherPayoutRequest.objects.create(
            publisher=locked_publisher,
            amount=amount,
            currency=locked_publisher.currency,
            payout_method=payout_method,
            publisher_note=str(publisher_note or "").strip()[:500],
            available_balance_snapshot=summary["available"],
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
                f"Payout cannot move from {locked.get_status_display()} to {new_status}."
            )
        reference = str(payment_reference or locked.payment_reference or "").strip()
        if new_status == PublisherPayoutRequest.Status.PAID and not reference:
            raise ValidationError("A payment reference is required before marking a payout paid.")
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
