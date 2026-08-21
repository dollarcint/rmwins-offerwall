from django.db import migrations, models


def assign_publisher_numbers(apps, schema_editor):
    Publisher = apps.get_model("offerwall", "Publisher")
    PublisherNumberSequence = apps.get_model("offerwall", "PublisherNumberSequence")
    next_value = 1
    for publisher in Publisher.objects.order_by("created_at", "pk").iterator():
        Publisher.objects.filter(pk=publisher.pk).update(publisher_number=next_value)
        next_value += 1
    PublisherNumberSequence.objects.update_or_create(
        key="publisher",
        defaults={"next_value": next_value},
    )


class Migration(migrations.Migration):
    dependencies = [("offerwall", "0008_opinionuniverse_parity")]

    operations = [
        migrations.CreateModel(
            name="PublisherNumberSequence",
            fields=[
                (
                    "key",
                    models.CharField(
                        default="publisher",
                        editable=False,
                        max_length=32,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "next_value",
                    models.PositiveBigIntegerField(default=1, editable=False),
                ),
            ],
        ),
        migrations.AddField(
            model_name="publisher",
            name="publisher_number",
            field=models.PositiveBigIntegerField(
                editable=False,
                null=True,
                unique=True,
            ),
        ),
        migrations.RunPython(assign_publisher_numbers, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="publisher",
            name="publisher_number",
            field=models.PositiveBigIntegerField(editable=False, unique=True),
        ),
    ]
