from django.db import models
from django.utils.translation import gettext_lazy as _


class ActionChoices(models.TextChoices):
    reject = 'reject', _('Reject')
    accept = 'accept', _('Accept')
    review = 'review', _('Review')
    face_review = 'face_review', _('Face + Review')
    warning = 'warning', _('Warning')
    notice = 'notice', _('Notifications')
