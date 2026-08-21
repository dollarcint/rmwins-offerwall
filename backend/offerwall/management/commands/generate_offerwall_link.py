import secrets

from django.core.management.base import BaseCommand, CommandError
from django.urls import reverse
from django.utils import timezone

from offerwall.models import Publisher
from offerwall.security import signed_entry_query
from offerwall.services import absolute_url


class Command(BaseCommand):
    help = "Generate one short-lived signed Offerwall entry URL for a publisher user."

    def add_arguments(self, parser):
        parser.add_argument("publisher_slug")
        parser.add_argument("external_user_id")

    def handle(self, *args, **options):
        try:
            publisher = Publisher.objects.get(slug=options["publisher_slug"], is_active=True)
        except Publisher.DoesNotExist as exc:
            raise CommandError("Active Offerwall publisher not found.") from exc
        external_user_id = str(options["external_user_id"] or "").strip()
        if not external_user_id or len(external_user_id) > 160:
            raise CommandError("external_user_id must contain 1-160 characters.")
        timestamp = int(timezone.now().timestamp())
        nonce = secrets.token_urlsafe(18)
        query = signed_entry_query(
            publisher,
            external_user_id=external_user_id,
            timestamp=timestamp,
            nonce=nonce,
        )
        path = reverse("offerwall:entry", kwargs={"publisher_slug": publisher.slug})
        self.stdout.write(absolute_url(f"{path}?{query}"))
