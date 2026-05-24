import base64
import json
import uuid
from decimal import Decimal
from pathlib import Path

import requests
from django.conf import settings
from django.core.cache import cache
from django.core.files.storage import default_storage
from django.utils.translation import gettext_lazy as _
from gmssl import func, sm2, sm3
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT


AI_FACE_TOKEN_CACHE_KEY = 'face_verify:ai_face:token'


class FaceCompareError(Exception):
    def __init__(self, message=None, response=None):
        self.message = str(message or _('AI face compare failed'))
        self.response = response or {}
        super().__init__(self.message)


class FaceCompareResult:
    def __init__(self, passed, score, threshold, response):
        self.passed = passed
        self.score = score
        self.threshold = threshold
        self.response = response


class FaceClient:
    json_type = 'application/json;charset=UTF-8'
    timeout = 30

    def __init__(self):
        self.base_url = settings.AI_FACE_BASE_URL.rstrip('/')
        self.app_id = settings.AI_FACE_APP_ID
        self.sign_key = settings.AI_FACE_SIGN_KEY
        self.sm4_key = settings.AI_FACE_SM4_KEY
        self.agent_id = settings.AI_FACE_AGENT_ID
        self.access_token = settings.AI_FACE_ACCESS_TOKEN

    def compare(self, face_image_path, photo_image_path, seq=''):
        self.validate_config()
        body = {
            'fileA': self.encrypt_image_base64(face_image_path),
            'fileB': self.encrypt_image_base64(photo_image_path),
            'seq': seq,
        }
        response = self.post_with_auth('/openapi/face/compare', body)
        return self.parse_compare_result(response)

    def validate_config(self):
        missing = []
        for name, value in [
            ('AI_FACE_BASE_URL', self.base_url),
            ('AI_FACE_APP_ID', self.app_id),
            ('AI_FACE_SIGN_KEY', self.sign_key),
            ('AI_FACE_SM4_KEY', self.sm4_key),
        ]:
            if not value:
                missing.append(name)
        if missing:
            raise FaceCompareError(_('Missing AI face config: {}').format(', '.join(missing)))

    def get_access_token(self):
        if self.access_token:
            return self.access_token
        cached = cache.get(AI_FACE_TOKEN_CACHE_KEY)
        if cached:
            return cached

        body = {'appId': self.app_id}
        response = self.post('/openapi/resource/getAccessToken', body, token_required=False)
        token_data = response.get('data') or {}
        token = token_data.get('accessToken') or token_data.get('access_token') or token_data.get('token')
        if not token:
            raise FaceCompareError(_('Get AI face access token failed'), response=response)
        ttl = (
            token_data.get('exp') or token_data.get('expires_in') or
            token_data.get('expiresIn') or settings.AI_FACE_TOKEN_CACHE_SECONDS
        )
        try:
            ttl = int(ttl) * 60
        except (TypeError, ValueError):
            ttl = settings.AI_FACE_TOKEN_CACHE_SECONDS
        cache.set(AI_FACE_TOKEN_CACHE_KEY, token, max(1, min(settings.AI_FACE_TOKEN_CACHE_SECONDS, ttl) - 5))
        return token

    def post_with_auth(self, path, body):
        return self.post(path, body, token_required=True)

    def post(self, path, body, token_required):
        json_body = self.dumps(body)
        headers = {
            'Content-Type': self.json_type,
            'X-Face-Data-Sign': self.sign(json_body),
            'X-Face-Clientid': self.app_id,
        }
        if token_required:
            headers['X-Face-AccessToken'] = self.get_access_token()
            if self.agent_id:
                headers['X-Face-AgentId'] = self.agent_id

        try:
            response = requests.post(
                self.base_url + path,
                data=json_body.encode('utf-8'),
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise FaceCompareError(e)

    @staticmethod
    def dumps(body):
        return json.dumps(body, ensure_ascii=False, separators=(',', ':'))

    def sign(self, request_body):
        sm3_hex = sm3.sm3_hash(func.bytes_to_list(request_body.encode('utf-8')))
        signer = sm2.CryptSM2(public_key='', private_key=self.sign_key, mode=1, asn1=True)
        return signer.sign(sm3_hex.encode('utf-8'), uuid.uuid4().hex + uuid.uuid4().hex)

    def encrypt_image_base64(self, image_path):
        if default_storage.exists(image_path):
            with default_storage.open(image_path, 'rb') as f:
                content = f.read()
        else:
            content = Path(image_path).read_bytes()
        image_base64 = base64.b64encode(content).decode('ascii')
        return self.sm4_encrypt_text(image_base64)

    def sm4_encrypt_text(self, text):
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(self.get_sm4_key_bytes(), SM4_ENCRYPT)
        encrypted = crypt_sm4.crypt_ecb(text.encode('utf-8'))
        return base64.b64encode(encrypted).decode('ascii')

    def get_sm4_key_bytes(self):
        key = self.sm4_key.strip()
        if len(key) == 32 and all(c in '0123456789abcdefABCDEF' for c in key):
            return bytes.fromhex(key)
        key_bytes = key.encode('utf-8')
        if len(key_bytes) >= 16:
            return key_bytes[:16]
        return key_bytes.ljust(16, b'\0')

    @staticmethod
    def parse_compare_result(response):
        if not is_response_success(response):
            raise FaceCompareError(_('AI face response code is not success'), response=response)
        data = response.get('data') or {}
        score = find_first_number(data, ('score', 'similarity', 'similar', 'confidence'))
        threshold = Decimal(str(settings.AI_FACE_PASS_THRESHOLD))
        response_threshold = find_first_number(data, ('threshold', 'passThreshold'))
        if response_threshold is not None:
            threshold = response_threshold

        passed = find_first_bool(data, ('passed', 'pass', 'success', 'samePerson', 'isSame'))
        if passed is None and score is not None:
            passed = score >= threshold
        if passed is None:
            raise FaceCompareError(_('AI face response does not contain compare result'), response=response)
        return FaceCompareResult(passed, score, threshold, response)


def find_first_number(data, keys):
    if not isinstance(data, dict):
        return None
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        try:
            return Decimal(str(value))
        except Exception:
            continue
    for value in data.values():
        if isinstance(value, dict):
            found = find_first_number(value, keys)
            if found is not None:
                return found
    return None


def find_first_bool(data, keys):
    if not isinstance(data, dict):
        return None
    for key in keys:
        value = data.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            if value.lower() in ('true', 'yes', '1', 'pass', 'passed', 'success'):
                return True
            if value.lower() in ('false', 'no', '0', 'fail', 'failed'):
                return False
        if isinstance(value, int):
            return value == 1
    for value in data.values():
        if isinstance(value, dict):
            found = find_first_bool(value, keys)
            if found is not None:
                return found
    return None


def is_response_success(response):
    code = response.get('code')
    if code is None:
        return True
    if isinstance(code, int):
        return code in (100001, 0, 200)
    return str(code).lower() in ('100001', '0', '200', 'success')
