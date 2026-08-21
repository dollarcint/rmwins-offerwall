import secrets

from django.core.management.base import BaseCommand, CommandError
from django.urls import reverse
from django.utils import timezone

from offerwall.models import Publisher
from offerwall.security import signed_portal_query
from offerwall.services import absolute_url


class Command(BaseCommand):
    help = "Generate one short-lived, one-time publisher wallet dashboard URL."

    def add_arguments(self, parser):
        parser.add_argument("publisher_slug")

    def handle(self, *args, **options):
        try:
            publisher = Publisher.objects.get(
                slug=options["publisher_slug"], is_active=True
            )
        except Publisher.DoesNotExist as exc:
            raise CommandError("Active Offerwall publisher not found.") from exc
        timestamp = int(timezone.now().timestamp())
        nonce = secrets.token_urlsafe(18)
        query = signed_portal_query(
            publisher, timestamp=timestamp, nonce=nonce
        )
        path = reverse(
            "offerwall:publisher-access",
            kwargs={"publisher_slug": publisher.slug},
        )
        self.stdout.write(absolute_url(f"{path}?{query}"))
