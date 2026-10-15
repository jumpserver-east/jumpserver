import uuid

from django.conf import settings
from django.db import models

__all__ = ['TicketRepairCode']


class TicketRepairCode(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ticket = models.ForeignKey(
        'tickets.ApplyAssetTicket', on_delete=models.CASCADE, related_name='repair_codes'
    )
    approver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    digest = models.CharField(max_length=64, unique=True, editable=False)
    used_at = models.DateTimeField(null=True, editable=False)

    class Meta:
        default_permissions = ()
