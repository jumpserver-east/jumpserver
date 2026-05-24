# Generated manually for command face verification records.

import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('authentication', '0024_accesskey_ip_group'),
    ]

    operations = [
        migrations.CreateModel(
            name='CommandFaceVerifyRecord',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('sign', models.CharField(blank=True, db_index=True, max_length=128, null=True, unique=True)),
                ('session_id', models.UUIDField(db_index=True)),
                ('user_id', models.CharField(blank=True, db_index=True, max_length=36)),
                ('asset_id', models.CharField(blank=True, db_index=True, max_length=36)),
                ('account_id', models.CharField(blank=True, db_index=True, max_length=128)),
                ('cmd_filter_acl_id', models.UUIDField(db_index=True)),
                ('ticket_id', models.UUIDField(blank=True, db_index=True, null=True)),
                ('run_command', models.TextField()),
                ('machine_ip', models.CharField(blank=True, max_length=128)),
                ('user_name', models.CharField(blank=True, max_length=128)),
                ('id_number_masked', models.CharField(blank=True, max_length=32)),
                ('status', models.CharField(choices=[
                    ('created', 'Created'),
                    ('token_failed', 'Token failed'),
                    ('camera_call_failed', 'Camera call failed'),
                    ('waiting_photo', 'Waiting photo'),
                    ('photo_received', 'Photo received'),
                    ('comparing', 'Comparing'),
                    ('passed', 'Passed'),
                    ('failed', 'Failed'),
                    ('timeout', 'Timeout'),
                    ('error', 'Error'),
                ], db_index=True, default='created', max_length=32)),
                ('score', models.DecimalField(blank=True, decimal_places=4, max_digits=8, null=True)),
                ('threshold', models.DecimalField(blank=True, decimal_places=4, max_digits=8, null=True)),
                ('ai_response', models.JSONField(blank=True, default=dict)),
                ('face_image_path', models.CharField(blank=True, max_length=512)),
                ('photo_image_path', models.CharField(blank=True, max_length=512)),
                ('face_image_sha256', models.CharField(blank=True, max_length=64)),
                ('photo_image_sha256', models.CharField(blank=True, max_length=64)),
                ('face_image_size', models.PositiveIntegerField(default=0)),
                ('photo_image_size', models.PositiveIntegerField(default=0)),
                ('error_message', models.TextField(blank=True)),
                ('date_callback', models.DateTimeField(blank=True, null=True)),
                ('date_compared', models.DateTimeField(blank=True, null=True)),
                ('date_finished', models.DateTimeField(blank=True, null=True)),
                ('org_id', models.CharField(blank=True, db_index=True, max_length=36)),
                ('date_created', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('date_updated', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Command face verify record',
                'ordering': ('-date_created',),
            },
        ),
    ]
