# Generated by Django 4.1.13 on 2024-10-21 09:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0007_alter_accountrisk_risk'),
    ]

    operations = [
        migrations.AddField(
            model_name='changesecretautomation',
            name='check_conn_after_change',
            field=models.BooleanField(default=True, verbose_name='Check connection after change'),
        ),
        migrations.AddField(
            model_name='pushaccountautomation',
            name='check_conn_after_change',
            field=models.BooleanField(default=True, verbose_name='Check connection after change'),
        ),
    ]
