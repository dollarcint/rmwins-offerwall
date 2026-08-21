from django.db import migrations, models


def use_product_platforms(apps, schema_editor):
    Placement = apps.get_model("offerwall", "PublisherPlacement")
    Placement.objects.filter(platform__in=("responsive", "desktop")).update(platform="web")
    Placement.objects.filter(platform="mobile").update(platform="android")


def restore_legacy_platforms(apps, schema_editor):
    Placement = apps.get_model("offerwall", "PublisherPlacement")
    Placement.objects.filter(platform="web").update(platform="responsive")
    Placement.objects.filter(platform__in=("android", "ios")).update(platform="mobile")


class Migration(migrations.Migration):
    dependencies = [("offerwall", "0005_remove_publisherplacement_placement_active_idx_and_more")]

    operations = [
        migrations.RunPython(use_product_platforms, restore_legacy_platforms),
        migrations.AlterField(
            model_name="publisherplacement",
            name="platform",
            field=models.CharField(
                choices=[("web", "Website"), ("android", "Android"), ("ios", "iOS")],
                default="web",
                max_length=12,
            ),
        ),
    ]
