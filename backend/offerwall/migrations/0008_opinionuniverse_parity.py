from django.db import migrations, models


def normalize_placement_contract(apps, schema_editor):
    Placement = apps.get_model("offerwall", "PublisherPlacement")
    for placement in Placement.objects.all().only(
        "pk", "currency_name", "postback_url"
    ).iterator():
        Placement.objects.filter(pk=placement.pk).update(
            currency_name=(placement.currency_name or "Points")[:6],
            respondent_id_parameter="SID",
            allowed_domains="",
            postback_enabled=bool(placement.postback_url),
        )


class Migration(migrations.Migration):
    dependencies = [("offerwall", "0007_placement_settings_suite")]

    operations = [
        migrations.AddField(
            model_name="publisher",
            name="encrypted_api_key",
            field=models.TextField(blank=True, editable=False),
        ),
        migrations.AddField(
            model_name="wallvisit",
            name="affiliate_sub_id_3",
            field=models.CharField(blank=True, default="", max_length=160),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="wallvisit",
            name="affiliate_sub_id_4",
            field=models.CharField(blank=True, default="", max_length=160),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="wallvisit",
            name="affiliate_sub_id_5",
            field=models.CharField(blank=True, default="", max_length=160),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="wallvisit",
            name="gaid",
            field=models.CharField(blank=True, default="", max_length=160),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="wallvisit",
            name="idfa",
            field=models.CharField(blank=True, default="", max_length=160),
            preserve_default=False,
        ),
        migrations.RunPython(normalize_placement_contract, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="publisherplacement",
            name="currency_name",
            field=models.CharField(default="Points", max_length=6),
        ),
    ]
