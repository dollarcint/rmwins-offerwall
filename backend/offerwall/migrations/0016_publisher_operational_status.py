from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def hydrate_operational_status(apps, schema_editor):
    Publisher = apps.get_model("offerwall", "Publisher")
    Publisher.objects.filter(is_active=False).update(operational_status="paused")


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("offerwall", "0015_offerwallinventoryrule_platform_cut_percent"),
    ]

    operations = [
        migrations.AddField(
            model_name="publisher",
            name="operational_note",
            field=models.CharField(blank=True, max_length=500),
        ),
        migrations.AddField(
            model_name="publisher",
            name="operational_status",
            field=models.CharField(
                choices=[
                    ("active", "Active"),
                    ("paused", "Paused"),
                    ("suspended", "Suspended"),
                ],
                db_index=True,
                default="active",
                max_length=12,
            ),
        ),
        migrations.AddField(
            model_name="publisher",
            name="operational_status_changed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="publisher",
            name="operational_status_changed_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="changed_offerwall_supplier_statuses",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.RunPython(hydrate_operational_status, migrations.RunPython.noop),
    ]
