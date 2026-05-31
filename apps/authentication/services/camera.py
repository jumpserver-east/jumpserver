import re
import time
from urllib.parse import urljoin

import requests
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from common.utils import get_logger

logger = get_logger(__file__)

ID_NUMBER_PATTERN = re.compile(r'\d{17}[\dXx]')
CAMERA_TOKEN_CACHE_KEY = 'face_verify:camera:token'
MAX_LOG_TEXT_LENGTH = 2048
SENSITIVE_LOG_PATTERN = re.compile(
    r'(?i)([\'"]?(?:authorization|accessToken|access_token|token|signData|idNumber|faceStr|photoStr)'
    r'[\'"]?\s*[:=]\s*[\'"]?)[^\'",\s}]+'
)


def redact_log_text(value):
    text = str(value or '')
    text = SENSITIVE_LOG_PATTERN.sub(r'\1***', text)
    if len(text) > MAX_LOG_TEXT_LENGTH:
        text = '{}...(truncated)'.format(text[:MAX_LOG_TEXT_LENGTH])
    return text


def format_response_for_log(response):
    if response is None:
        return ''
    return redact_log_text(response.text)


class CameraSystemError(Exception):
    code = 'face_verify_camera_failed'

    def __init__(self, message=None):
        self.message = str(message or _('Camera system error'))
        super().__init__(self.message)


class CameraTokenError(CameraSystemError):
    code = 'face_verify_token_failed'


class IDNumberError(CameraSystemError):
    code = 'face_verify_id_number_invalid'


def extract_id_number(comment):
    values = ID_NUMBER_PATTERN.findall(comment or '')
    values = [i.upper() for i in values]
    if not values:
        raise IDNumberError(_('ID number is missing in user comment'))
    if len(values) > 1:
        raise IDNumberError(_('Multiple ID numbers found in user comment'))
    return values[0]


def mask_id_number(id_number):
    if not id_number or len(id_number) < 8:
        return ''
    return '{}{}{}'.format(id_number[:3], '*' * 11, id_number[-4:])


class CameraSystemClient:
    timeout = 10

    def __init__(self):
        self.base_url = settings.CAMERA_SYSTEM_BASE_URL.rstrip('/') + '/'

    def get_token(self):
        cached = cache.get(CAMERA_TOKEN_CACHE_KEY)
        if cached:
            return cached

        url = urljoin(self.base_url, 'auth/outerLogin')
        payload = {'signData': settings.CAMERA_SYSTEM_SIGN_DATA}
        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
        except Exception as e:
            logger.warning('Get camera token request failed: url=%s error=%s', url, e)
            raise CameraTokenError(e)

        try:
            data = response.json()
        except Exception as e:
            logger.warning(
                'Get camera token response invalid: url=%s status=%s response=%s error=%s',
                url, response.status_code, format_response_for_log(response), e
            )
            raise CameraTokenError(e)

        token_data = data.get('data') or {}
        token = token_data.get('token')
        if data.get('code') != 200 or not token:
            logger.warning(
                'Get camera token failed: url=%s status=%s response=%s',
                url, response.status_code, format_response_for_log(response)
            )
            raise CameraTokenError(data.get('msg') or _('Get camera token failed'))

        expires_in = token_data.get('expires_in') or settings.CAMERA_TOKEN_CACHE_SECONDS
        try:
            expires_in = int(expires_in)
        except (TypeError, ValueError):
            expires_in = settings.CAMERA_TOKEN_CACHE_SECONDS
        ttl = max(1, min(settings.CAMERA_TOKEN_CACHE_SECONDS, expires_in * 60) - 5)
        cache.set(CAMERA_TOKEN_CACHE_KEY, token, ttl)
        return token

    def call_camera(self, machine_ip, user_name, id_number):
        token = self.get_token()
        url = urljoin(self.base_url, 'cs/external/machine/callCamera')
        headers = {'Authorization': 'Bearer {}'.format(token)}
        params = {
            'machineIp': machine_ip,
            'userName': user_name,
            'idNumber': id_number,
        }
        logger.info(
            'Call camera: machine_ip=%s user_name=%s id_number=%s',
            machine_ip, user_name, mask_id_number(id_number)
        )
        try:
            response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
        except Exception as e:
            logger.warning(
                'Call camera request failed: url=%s machine_ip=%s user_name=%s id_number=%s error=%s',
                url, machine_ip, user_name, mask_id_number(id_number), e
            )
            raise CameraSystemError(e)

        try:
            data = response.json()
        except Exception as e:
            logger.warning(
                'Call camera response invalid: url=%s machine_ip=%s user_name=%s id_number=%s '
                'status=%s response=%s error=%s',
                url, machine_ip, user_name, mask_id_number(id_number),
                response.status_code, format_response_for_log(response), e
            )
            raise CameraSystemError(e)

        sign = (data.get('data') or {}).get('sign')
        if data.get('code') != 200 or not sign:
            logger.warning(
                'Call camera failed: url=%s machine_ip=%s user_name=%s id_number=%s '
                'status=%s response=%s',
                url, machine_ip, user_name, mask_id_number(id_number),
                response.status_code, format_response_for_log(response)
            )
            raise CameraSystemError(data.get('msg') or _('Call camera failed'))
        return sign


def trigger_command_face_verify(run_command, session, cmd_filter_acl, org_id):
    from authentication.models import CommandFaceVerifyRecord

    user = session.user_obj
    machine_ip = session.remote_addr or ''
    user_name = user.name
    record = CommandFaceVerifyRecord.objects.create(
        session_id=session.id,
        user_id=session.user_id,
        asset_id=session.asset_id,
        account_id=session.account_id,
        cmd_filter_acl_id=cmd_filter_acl.id,
        run_command=run_command[:4090],
        machine_ip=machine_ip,
        user_name=user_name,
        org_id=org_id,
    )
    try:
        id_number = extract_id_number(user.comment)
        record.id_number_masked = mask_id_number(id_number)
        record.save(update_fields=['id_number_masked', 'date_updated'])
        sign = CameraSystemClient().call_camera(machine_ip, user_name, id_number)
        record.sign = sign
        record.status = CommandFaceVerifyRecord.StatusChoices.waiting_photo
        record.error_message = ''
        record.save(update_fields=['sign', 'status', 'error_message', 'date_updated'])
    except CameraTokenError as e:
        record.status = CommandFaceVerifyRecord.StatusChoices.token_failed
        record.error_message = e.message
        record.save(update_fields=['status', 'error_message', 'date_updated'])
        logger.warning('Command face verify token failed: record=%s error=%s', record.id, e.message)
    except CameraSystemError as e:
        record.status = (
            CommandFaceVerifyRecord.StatusChoices.error
            if isinstance(e, IDNumberError)
            else CommandFaceVerifyRecord.StatusChoices.camera_call_failed
        )
        record.error_message = e.message
        record.save(update_fields=['status', 'error_message', 'date_updated'])
        logger.warning('Command face verify camera failed: record=%s error=%s', record.id, e.message)
    return record


def wait_command_face_verify(record):
    from authentication.models import CommandFaceVerifyRecord

    deadline = time.time() + settings.CAMERA_PHOTO_TIMEOUT_SECONDS
    final_statuses = (
        CommandFaceVerifyRecord.StatusChoices.passed,
        CommandFaceVerifyRecord.StatusChoices.failed,
        CommandFaceVerifyRecord.StatusChoices.error,
        CommandFaceVerifyRecord.StatusChoices.token_failed,
        CommandFaceVerifyRecord.StatusChoices.camera_call_failed,
    )
    while time.time() < deadline:
        record.refresh_from_db()
        if record.status in final_statuses:
            return record
        time.sleep(0.5)

    record.status = CommandFaceVerifyRecord.StatusChoices.timeout
    record.error_message = _('Camera photo callback timeout')
    record.date_finished = timezone.now()
    record.save(update_fields=['status', 'error_message', 'date_finished', 'date_updated'])
    return record
