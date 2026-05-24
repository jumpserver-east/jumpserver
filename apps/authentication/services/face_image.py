import base64
import binascii
import hashlib
import os

from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers


def decode_base64_image(value):
    value = (value or '').strip()
    if ',' in value and value.lower().startswith('data:'):
        value = value.split(',', 1)[1]
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise serializers.ValidationError(_('Invalid base64 image data'))


def get_image_ext(content):
    if content.startswith(b'\xff\xd8\xff'):
        return 'jpg'
    if content.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    return 'jpg'


def save_face_verify_image(record, content, name):
    date = timezone.localtime().strftime('%Y/%m/%d')
    ext = get_image_ext(content)
    path = os.path.join('face_verify', date, str(record.id), '{}.{}'.format(name, ext))
    if default_storage.exists(path):
        default_storage.delete(path)
    saved_path = default_storage.save(path, ContentFile(content))
    return {
        'path': saved_path,
        'sha256': hashlib.sha256(content).hexdigest(),
        'size': len(content),
    }
