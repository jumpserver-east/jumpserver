import base64
import binascii
import hashlib
import os
from io import BytesIO

from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from PIL import Image, ImageOps


MAX_FACE_IMAGE_SIZE = 100 * 1024
JPEG_QUALITIES = (90, 80, 70, 60, 50, 40, 30)
FALLBACK_JPEG_QUALITIES = (25, 20)
FALLBACK_MAX_SIDES = (480, 320, 240, 160)
MIN_IMAGE_SIDE = 32
SCALE_STEP = 0.9


def decode_base64_image(value):
    value = (value or '').strip()
    if ',' in value and value.lower().startswith('data:'):
        value = value.split(',', 1)[1]
    try:
        content = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise serializers.ValidationError(_('Invalid base64 image data'))
    if not content:
        raise serializers.ValidationError(_('Image data is empty'))
    return content


def get_image_ext(content):
    if content.startswith(b'\xff\xd8\xff'):
        return 'jpg'
    if content.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    return 'jpg'


def compress_image(content):
    if len(content) <= MAX_FACE_IMAGE_SIZE:
        return content

    try:
        image = Image.open(BytesIO(content))
        image = ImageOps.exif_transpose(image).convert('RGB')
    except Exception:
        raise serializers.ValidationError(_('Invalid image data'))

    for attempt in range(80):
        data = compress_image_with_qualities(image, JPEG_QUALITIES)
        if data:
            return data

        width, height = image.size
        if min(width, height) <= MIN_IMAGE_SIDE:
            break
        image = image.resize((
            max(MIN_IMAGE_SIDE, int(width * SCALE_STEP)),
            max(MIN_IMAGE_SIDE, int(height * SCALE_STEP)),
        ), Image.LANCZOS)

    data = compress_image_fallback(image)
    if data:
        return data
    raise serializers.ValidationError(_('Image is too large to compress'))


def compress_image_with_qualities(image, qualities):
    for quality in qualities:
        output = BytesIO()
        image.save(output, format='JPEG', quality=quality, optimize=True)
        data = output.getvalue()
        if len(data) <= MAX_FACE_IMAGE_SIZE:
            return data
    return None


def compress_image_fallback(image):
    for max_side in FALLBACK_MAX_SIDES:
        fallback = image.copy()
        fallback.thumbnail((max_side, max_side), Image.LANCZOS)
        data = compress_image_with_qualities(fallback, FALLBACK_JPEG_QUALITIES)
        if data:
            return data
    return None


def save_face_verify_image(record, content, name):
    content = compress_image(content)
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
