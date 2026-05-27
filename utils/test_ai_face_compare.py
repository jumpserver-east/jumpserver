#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import sys
import time
import uuid
from urllib import error as url_error
from urllib import request as url_request

TOKEN_URL = '/openapi/resource/getAccessToken'
COMPARE_URL = '/openapi/face/compare'
JSON_TYPE = 'application/json;charset=UTF-8'

AI_FACE_BASE_URL = 'http://localhost:18080'
AI_FACE_APP_ID = '6435e616f311b23dd6561980ebd'
AI_FACE_SIGN_KEY = '0309540920CA56551A7D169E413220925C463922898D'
AI_FACE_SM4_KEY = '0613160931302077172'
AI_FACE_ACCESS_TOKEN = ''
AI_FACE_PASS_THRESHOLD = 0.8

# 1x1 PNG。fileA/fileB 都使用它，确保两张“假图片”完全一致。
# 如果 AI 平台强校验人脸，这张图可能会返回“未检测到人脸”，但能验证 token、签名、加密和请求链路。
PLACEHOLDER_IMAGE_BASE64 = (
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8'
    '/x8AAwMCAO+/p9sAAAAASUVORK5CYII='
)


def mask(value, left=6, right=4):
    if value is None:
        return ''
    return str(value)


def step(title):
    print('\n=== {} ==='.format(title), flush=True)


def compact_json(data):
    return json.dumps(data, ensure_ascii=False, separators=(',', ':'))


def pretty_json(data):
    return json.dumps(data, ensure_ascii=False, indent=2)


def summarize_value(value):
    text = str(value)
    return {
        'length': len(text),
        'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(),
        'preview': mask(text, 10, 8),
    }


def summarize_body(body):
    summary = {}
    for key, value in body.items():
        if key in ('fileA', 'fileB', 'data'):
            summary[key] = summarize_value(value)
        else:
            summary[key] = value
    return summary


def parse_args():
    parser = argparse.ArgumentParser(
        description='Complete AI face platform test: get accessToken, then compare two same fake images.'
    )
    parser.add_argument('--seq', default='debug-fake-image-compare', help='request sequence value')
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument(
        '--token-only',
        action='store_true',
        help='only call /openapi/resource/getAccessToken',
    )
    return parser.parse_args()


class FaceApiDebugClient:
    def __init__(self, args):
        self.base_url = AI_FACE_BASE_URL.rstrip('/')
        self.app_id = AI_FACE_APP_ID
        self.sign_key = AI_FACE_SIGN_KEY
        self.sm4_key = AI_FACE_SM4_KEY
        self.access_token = AI_FACE_ACCESS_TOKEN
        self.threshold = AI_FACE_PASS_THRESHOLD
        self.timeout = args.timeout

    def validate_config(self):
        self.validate_dependencies()
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
            raise RuntimeError('missing config: {}'.format(', '.join(missing)))

    @staticmethod
    def validate_dependencies():
        missing = []
        for module_name in ('gmssl',):
            try:
                __import__(module_name)
            except ImportError:
                missing.append(module_name)
        if missing:
            raise RuntimeError(
                'missing python packages: {}. Try running in the project environment, '
                'or install them with: pip install {}'.format(
                    ', '.join(missing),
                    ' '.join(missing),
                )
            )

    def get_access_token(self):
        body = {'appId': self.app_id}
        response = self.post(TOKEN_URL, body, token_required=False)
        data = response.get('data') or {}
        token = data.get('accessToken') or data.get('access_token') or data.get('token')
        if not token:
            raise RuntimeError('access token missing in response: {}'.format(response))
        self.access_token = token
        print('accessToken: {}'.format(mask(token, 10, 6)))
        print('expires: {}'.format(data.get('exp') or data.get('expires_in') or data.get('expiresIn')))
        return token

    def compare(self, seq):
        body = {
            'fileA': self.encrypt_fake_image_base64('fileA'),
            'fileB': self.encrypt_fake_image_base64('fileB'),
            'seq': seq,
        }
        response = self.post(COMPARE_URL, body, token_required=True)
        self.check_response_code(response, 'compare')
        data = response.get('data') or {}
        score = self.find_first_number(data, ('score', 'similarity', 'similar', 'confidence'))
        threshold = self.find_first_number(data, ('threshold', 'passThreshold'))
        if threshold is None:
            threshold = self.parse_number(self.threshold)
        passed = self.find_first_bool(data, ('passed', 'pass', 'success', 'samePerson', 'isSame'))
        if passed is None and score is not None and threshold is not None:
            passed = score >= threshold

        print('compare data: {}'.format(pretty_json(data)))
        print('parsed passed: {}'.format(passed))
        print('parsed score: {}'.format(score))
        print('parsed threshold: {}'.format(threshold))
        return response

    def post(self, path, body, token_required):
        json_body = compact_json(body)
        data_sign = self.sign(json_body)
        headers = {
            'Content-Type': JSON_TYPE,
            'X-Face-Data-Sign': data_sign,
            'X-Face-Clientid': self.app_id,
        }
        if token_required:
            if not self.access_token:
                raise RuntimeError('access token is empty; call get_access_token first')
            headers['X-Face-AccessToken'] = self.access_token

        url = self.base_url + path
        self.print_request_debug(url, headers, body, json_body)

        started_at = time.time()
        http_status, response_text = self.post_by_urllib(url, headers, json_body)
        elapsed_ms = int((time.time() - started_at) * 1000)

        print('HTTP status: {}'.format(http_status))
        print('elapsed: {} ms'.format(elapsed_ms))
        print('raw response: {}'.format(response_text))
        if http_status >= 400:
            raise RuntimeError('HTTP {}: {}'.format(http_status, response_text))
        try:
            return json.loads(response_text)
        except ValueError as exc:
            raise RuntimeError('response is not JSON') from exc

    def post_by_urllib(self, url, headers, json_body):
        request = url_request.Request(
            url,
            data=json_body.encode('utf-8'),
            headers=headers,
            method='POST',
        )
        try:
            with url_request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode('utf-8', errors='replace')
                return response.status, body
        except url_error.HTTPError as exc:
            body = exc.read().decode('utf-8', errors='replace')
            return exc.code, body
        except url_error.URLError as exc:
            raise RuntimeError('request failed: {}'.format(exc)) from exc

    @staticmethod
    def check_response_code(response, api_name):
        if response.get('code') is None:
            return
        code = str(response.get('code'))
        if code.lower() not in ('100001', '0', '200', 'success'):
            raise RuntimeError(
                '{} failed, code={}, message={}, response={}'.format(
                    api_name,
                    response.get('code'),
                    response.get('message') or response.get('msg'),
                    response,
                )
            )

    def print_request_debug(self, url, headers, body, json_body):
        safe_headers = {}
        for key, value in headers.items():
            if key in ('X-Face-Data-Sign', 'X-Face-AccessToken'):
                safe_headers[key] = mask(value, 10, 8)
            else:
                safe_headers[key] = value
        print('URL: {}'.format(url))
        print('headers: {}'.format(pretty_json(safe_headers)))
        print('body summary: {}'.format(pretty_json(summarize_body(body))))
        print('body length: {}'.format(len(json_body.encode('utf-8'))))
        print('body sha256: {}'.format(hashlib.sha256(json_body.encode('utf-8')).hexdigest()))

    def sign(self, request_body):
        from gmssl import func, sm2, sm3

        sm3_hex = sm3.sm3_hash(func.bytes_to_list(request_body.encode('utf-8')))
        print('SM3(request body): {}'.format(sm3_hex))
        signer = sm2.CryptSM2(public_key='', private_key=self.sign_key, mode=1, asn1=True)
        random_hex = uuid.uuid4().hex + uuid.uuid4().hex
        sign = signer.sign(sm3_hex.encode('utf-8'), random_hex)
        print('SM2 sign: {}'.format(mask(sign, 12, 12)))
        return sign

    def encrypt_fake_image_base64(self, label):
        content = base64.b64decode(PLACEHOLDER_IMAGE_BASE64)
        image_base64 = PLACEHOLDER_IMAGE_BASE64
        encrypted = self.sm4_encrypt_text(image_base64)
        print(
            '{} fake image bytes: {}, base64 length: {}, encrypted length: {}, encrypted sha256: {}'.format(
                label,
                len(content),
                len(image_base64),
                len(encrypted),
                hashlib.sha256(encrypted.encode('utf-8')).hexdigest(),
            )
        )
        return encrypted

    def sm4_encrypt_text(self, text):
        from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(self.get_sm4_key_bytes(), SM4_ENCRYPT)
        encrypted = crypt_sm4.crypt_ecb(text.encode('utf-8'))
        return base64.b64encode(encrypted).decode('ascii')

    def get_sm4_key_bytes(self):
        key = self.sm4_key.strip()
        if len(key) == 32 and all(c in '0123456789abcdefABCDEF' for c in key):
            print('SM4 key mode: 32-char hex -> 16 bytes')
            return bytes.fromhex(key)

        key_bytes = key.encode('utf-8')
        if len(key_bytes) >= 16:
            print('SM4 key mode: utf-8 string, using first 16 bytes')
            return key_bytes[:16]

        print('SM4 key mode: utf-8 string shorter than 16 bytes, right padded with zeros')
        return key_bytes.ljust(16, b'\0')

    @staticmethod
    def parse_number(value):
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def find_first_number(cls, data, keys):
        if not isinstance(data, dict):
            return None
        for key in keys:
            value = cls.parse_number(data.get(key))
            if value is not None:
                return value
        for value in data.values():
            if isinstance(value, dict):
                found = cls.find_first_number(value, keys)
                if found is not None:
                    return found
        return None

    @classmethod
    def find_first_bool(cls, data, keys):
        if not isinstance(data, dict):
            return None
        for key in keys:
            value = data.get(key)
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                value = value.lower()
                if value in ('true', 'yes', '1', 'pass', 'passed', 'success'):
                    return True
                if value in ('false', 'no', '0', 'fail', 'failed'):
                    return False
            if isinstance(value, int):
                return value == 1
        for value in data.values():
            if isinstance(value, dict):
                found = cls.find_first_bool(value, keys)
                if found is not None:
                    return found
        return None


def main():
    args = parse_args()
    client = FaceApiDebugClient(args)
    try:
        client.validate_config()
        step('0. 当前配置')
        print('baseUrl: {}'.format(client.base_url))
        print('appId: {}'.format(client.app_id))
        print('signKey: {}'.format(mask(client.sign_key, 10, 8)))
        print('sm4Key: {}'.format(mask(client.sm4_key, 8, 6)))
        print('threshold: {}'.format(client.threshold))
        print('fake image sha256: {}'.format(
            hashlib.sha256(base64.b64decode(PLACEHOLDER_IMAGE_BASE64)).hexdigest()
        ))

        step('1. 获取访问令牌')
        if client.access_token:
            print('using configured access token: {}'.format(mask(client.access_token, 10, 6)))
        else:
            client.get_access_token()

        if args.token_only:
            return 0

        step('2. 人脸 1:1 比对（fileA/fileB 使用同一张内置假图）')
        client.compare(args.seq)
        return 0
    except Exception as exc:
        print('\nERROR: {}'.format(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
