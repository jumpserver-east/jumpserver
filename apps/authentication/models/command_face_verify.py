import uuid

from django.db import models
from django.utils.translation import gettext_lazy as _


class CommandFaceVerifyRecord(models.Model):
    class StatusChoices(models.TextChoices):
        created = 'created', _('Created')
        token_failed = 'token_failed', _('Token failed')
        camera_call_failed = 'camera_call_failed', _('Camera call failed')
        waiting_photo = 'waiting_photo', _('Waiting photo')
        photo_received = 'photo_received', _('Photo received')
        comparing = 'comparing', _('Comparing')
        passed = 'passed', _('Passed')
        failed = 'failed', _('Failed')
        timeout = 'timeout', _('Timeout')
        error = 'error', _('Error')

    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    sign = models.CharField(max_length=128, unique=True, null=True, blank=True, db_index=True)
    session_id = models.UUIDField(db_index=True)
    user_id = models.CharField(max_length=36, blank=True, db_index=True)
    asset_id = models.CharField(max_length=36, blank=True, db_index=True)
    account_id = models.CharField(max_length=128, blank=True, db_index=True)
    cmd_filter_acl_id = models.UUIDField(db_index=True)
    ticket_id = models.UUIDField(null=True, blank=True, db_index=True)
    run_command = models.TextField()
    machine_ip = models.CharField(max_length=128, blank=True)
    user_name = models.CharField(max_length=128, blank=True)
    id_number_masked = models.CharField(max_length=32, blank=True)
    status = models.CharField(
        max_length=32, choices=StatusChoices.choices,
        default=StatusChoices.created, db_index=True
    )
    score = models.DecimalField(max_digits=8, decimal_places=4, null=True, blank=True)
    threshold = models.DecimalField(max_digits=8, decimal_places=4, null=True, blank=True)
    ai_response = models.JSONField(default=dict, blank=True)
    face_image_path = models.CharField(max_length=512, blank=True)
    photo_image_path = models.CharField(max_length=512, blank=True)
    face_image_sha256 = models.CharField(max_length=64, blank=True)
    photo_image_sha256 = models.CharField(max_length=64, blank=True)
    face_image_size = models.PositiveIntegerField(default=0)
    photo_image_size = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)
    date_callback = models.DateTimeField(null=True, blank=True)
    date_compared = models.DateTimeField(null=True, blank=True)
    date_finished = models.DateTimeField(null=True, blank=True)
    org_id = models.CharField(max_length=36, blank=True, db_index=True)
    date_created = models.DateTimeField(auto_now_add=True, db_index=True)
    date_updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('-date_created',)
        verbose_name = _('Command face verify record')

    def __str__(self):
        return str(self.sign or self.id)
