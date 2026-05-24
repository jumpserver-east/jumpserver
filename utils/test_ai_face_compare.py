#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from urllib import error as url_error
from urllib import request as url_request

TOKEN_URL = '/openapi/resource/getAccessToken'
COMPARE_URL = '/openapi/face/compare'
JSON_TYPE = 'application/json;charset=UTF-8'

# 默认配置来自 Java 示例截图。也可以用命令行参数或环境变量覆盖。
DEFAULT_BASE_URL = 'http://25.86.167.195:18082'
DEFAULT_APP_ID = 'c79a55abbcfb249ba37de3rc4ac267ea67'
DEFAULT_SIGN_KEY = '00D4ED7F306FDC9949DD249EF23FD1C14615572930A1EBAFF98FCB563A33A4F4D89D'
DEFAULT_SM4_KEY = 'e2e2d245a5b34fc48dc4e5dd6181cdc8'
DEFAULT_AGENT_ID = '123456789'

# 1x1 PNG。默认 fileA/fileB 都使用它，确保两张“假图片”完全一致。
# 如果接口强校验人脸，这张图可能会返回“未检测到人脸”，但能验证签名、加密和请求链路。
PLACEHOLDER_IMAGE_BASE64 = (
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8'
    '/x8AAwMCAO+/p9sAAAAASUVORK5CYII='
)


def mask(value, left=6, right=4):
    if value is None:
        return ''
    value = str(value)
    if len(value) <= left + right:
        return '*' * len(value)
    return '{}{}{}'.format(value[:left], '*' * (len(value) - left - right), value[-right:])


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
        description='Python debug demo for getAccessToken and face 1:1 compare APIs.'
    )
    parser.add_argument('--base-url', default=os.getenv('AI_FACE_BASE_URL', DEFAULT_BASE_URL))
    parser.add_argument('--app-id', default=os.getenv('AI_FACE_APP_ID', DEFAULT_APP_ID))
    parser.add_argument('--sign-key', default=os.getenv('AI_FACE_SIGN_KEY', DEFAULT_SIGN_KEY))
    parser.add_argument('--sm4-key', default=os.getenv('AI_FACE_SM4_KEY', DEFAULT_SM4_KEY))
    parser.add_argument('--agent-id', default=os.getenv('AI_FACE_AGENT_ID', DEFAULT_AGENT_ID))
    parser.add_argument('--access-token', default=os.getenv('AI_FACE_ACCESS_TOKEN', ''))
    parser.add_argument('--image-a', help='first face image path')
    parser.add_argument('--image-b', help='second face image path; defaults to image-a, or fake image')
    parser.add_argument('--seq', default='111', help='request sequence value')
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument(
        '--token-only',
        action='store_true',
        help='only call /openapi/resource/getAccessToken',
    )
    return parser.parse_args()


class FaceApiDebugClient:
    def __init__(self, args):
        self.base_url = args.base_url.rstrip('/')
        self.app_id = args.app_id
        self.sign_key = args.sign_key
        self.sm4_key = args.sm4_key
        self.agent_id = args.agent_id
        self.access_token = args.access_token
        self.timeout = args.timeout

    def validate_config(self):
        self.validate_dependencies()
        missing = []
        for name, value in [
            ('AI_FACE_BASE_URL or --base-url', self.base_url),
            ('AI_FACE_APP_ID or --app-id', self.app_id),
            ('AI_FACE_SIGN_KEY or --sign-key', self.sign_key),
            ('AI_FACE_SM4_KEY or --sm4-key', self.sm4_key),
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

    def compare(self, image_a, image_b, seq):
        image_b = image_b or image_a
        body = {
            'fileA': self.encrypt_image_base64(image_a, 'image-a'),
            'fileB': self.encrypt_image_base64(image_b, 'image-b'),
            'seq': seq,
        }
        response = self.post(COMPARE_URL, body, token_required=True)
        self.check_success(response, 'compare')
        data = response.get('data') or {}
        print('score: {}'.format(data.get('score')))
        print('compare data: {}'.format(pretty_json(data)))
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
            if self.agent_id:
                headers['X-Face-AgentId'] = self.agent_id

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
    def check_success(response, api_name):
        code = str(response.get('code'))
        if code != '100001':
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

    def encrypt_image_base64(self, image_path, label):
        if image_path:
            path = Path(image_path).expanduser()
            content = path.read_bytes()
            print('{} path: {}'.format(label, path))
        else:
            content = base64.b64decode(PLACEHOLDER_IMAGE_BASE64)
            print('{} path: not provided, using 1x1 placeholder image'.format(label))

        image_base64 = base64.b64encode(content).decode('ascii')
        encrypted = self.sm4_encrypt_text(image_base64)
        print(
            '{} bytes: {}, base64 length: {}, encrypted length: {}, encrypted sha256: {}'.format(
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
        print('agentId: {}'.format(client.agent_id))
        if 'r' in client.app_id.lower():
            print('WARN: appId contains "r"; please confirm it is not a copied OCR typo.')

        step('1. 获取访问令牌')
        if client.access_token:
            print('using configured access token: {}'.format(mask(client.access_token, 10, 6)))
        else:
            client.get_access_token()

        if args.token_only:
            return 0

        step('2. 人脸 1:1 比对')
        client.compare(args.image_a, args.image_b, args.seq)
        return 0
    except Exception as exc:
        print('\nERROR: {}'.format(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
