# Generated by Django 4.2.3 on 2023-11-30 12:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('room', '0004_changeroomrequest'),
    ]

    operations = [
        migrations.AddField(
            model_name='changeroomrequest',
            name='email',
            field=models.EmailField(blank=True, max_length=255),
        ),
    ]
