import base64
import json
import secrets
from decimal import Decimal
from pathlib import Path

import requests
from django.conf import settings
from django.core.cache import cache
from django.core.files.storage import default_storage
from django.utils.translation import gettext_lazy as _


AI_FACE_TOKEN_CACHE_KEY = 'face_verify:ai_face:token'
SM2_P = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
SM2_A = 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc
SM2_B = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93
SM2_N = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123
SM2_GX = 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7
SM2_GY = 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0
SM2_DEFAULT_ID = b'1234567812345678'

SM4_SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]
SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
SM4_CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
]


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
        try:
            validate_hex_key('AI_FACE_SIGN_KEY', self.sign_key, 64)
            validate_hex_key('AI_FACE_SM4_KEY', self.sm4_key, 32)
        except ValueError as e:
            raise FaceCompareError(e)

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
        sm3_hex = sm3_hash(request_body.encode('utf-8')).hex().upper()
        return sm2_sign_asn1(self.sign_key, sm3_hex.encode('utf-8')).hex().upper()

    def encrypt_image_base64(self, image_path):
        if default_storage.exists(image_path):
            with default_storage.open(image_path, 'rb') as f:
                content = f.read()
        else:
            content = Path(image_path).read_bytes()
        image_base64 = base64.b64encode(content).decode('ascii')
        return self.sm4_encrypt_text(image_base64)

    def sm4_encrypt_text(self, text):
        round_keys = sm4_round_keys(self.get_sm4_key_bytes())
        encrypted = b''.join(
            sm4_encrypt_block(block, round_keys)
            for block in chunks(pkcs7_pad(text.encode('utf-8')), 16)
        )
        return encrypted.hex().upper()

    def get_sm4_key_bytes(self):
        key = self.sm4_key.strip()
        validate_hex_key('AI_FACE_SM4_KEY', key, 32)
        return bytes.fromhex(key)

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


def validate_hex_key(name, value, expected_length):
    if len(value) != expected_length or any(c not in '0123456789abcdefABCDEF' for c in value):
        raise ValueError(_('{} must be a {}-char hex string').format(name, expected_length))


def rotate_left(value, bits):
    return ((value << bits) & 0xffffffff) | (value >> (32 - bits))


def bytes_to_words(data):
    return [int.from_bytes(data[index:index + 4], 'big') for index in range(0, len(data), 4)]


def chunks(data, size):
    for index in range(0, len(data), size):
        yield data[index:index + size]


def sm3_hash(data):
    iv = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
    ]
    bit_length = len(data) * 8
    padded = data + b'\x80'
    padded += b'\x00' * ((56 - len(padded) % 64) % 64)
    padded += bit_length.to_bytes(8, 'big')

    state = iv[:]
    for block_start in range(0, len(padded), 64):
        block = padded[block_start:block_start + 64]
        w = bytes_to_words(block) + [0] * 52
        for j in range(16, 68):
            value = w[j - 16] ^ w[j - 9] ^ rotate_left(w[j - 3], 15)
            w[j] = value ^ rotate_left(value, 15) ^ rotate_left(value, 23) ^ rotate_left(w[j - 13], 7) ^ w[j - 6]
            w[j] &= 0xffffffff
        w1 = [(w[j] ^ w[j + 4]) & 0xffffffff for j in range(64)]

        a, b, c, d, e, f, g, h = state
        for j in range(64):
            constant = 0x79cc4519 if j <= 15 else 0x7a879d8a
            ss1 = rotate_left((rotate_left(a, 12) + e + rotate_left(constant, j % 32)) & 0xffffffff, 7)
            ss2 = ss1 ^ rotate_left(a, 12)
            if j <= 15:
                ff = a ^ b ^ c
                gg = e ^ f ^ g
            else:
                ff = (a & b) | (a & c) | (b & c)
                gg = (e & f) | ((~e) & g)
            tt1 = (ff + d + ss2 + w1[j]) & 0xffffffff
            tt2 = (gg + h + ss1 + w[j]) & 0xffffffff
            d = c
            c = rotate_left(b, 9)
            b = a
            a = tt1
            h = g
            g = rotate_left(f, 19)
            f = e
            e = (tt2 ^ rotate_left(tt2, 9) ^ rotate_left(tt2, 17)) & 0xffffffff
        state = [left ^ right for left, right in zip(state, [a, b, c, d, e, f, g, h])]

    return b''.join(word.to_bytes(4, 'big') for word in state)


def sm4_substitute(value):
    return (
        (SM4_SBOX[(value >> 24) & 0xff] << 24)
        | (SM4_SBOX[(value >> 16) & 0xff] << 16)
        | (SM4_SBOX[(value >> 8) & 0xff] << 8)
        | SM4_SBOX[value & 0xff]
    )


def sm4_key_round(value):
    value = sm4_substitute(value)
    return (value ^ rotate_left(value, 13) ^ rotate_left(value, 23)) & 0xffffffff


def sm4_round(value):
    value = sm4_substitute(value)
    return (value ^ rotate_left(value, 2) ^ rotate_left(value, 10) ^ rotate_left(value, 18) ^ rotate_left(value, 24)) & 0xffffffff


def sm4_round_keys(key):
    words = bytes_to_words(key)
    key_state = [word ^ fk for word, fk in zip(words, SM4_FK)]
    round_keys = []
    for index in range(32):
        next_key = key_state[index] ^ sm4_key_round(
            key_state[index + 1] ^ key_state[index + 2] ^ key_state[index + 3] ^ SM4_CK[index]
        )
        next_key &= 0xffffffff
        key_state.append(next_key)
        round_keys.append(next_key)
    return round_keys


def sm4_encrypt_block(block, round_keys):
    words = bytes_to_words(block)
    for index in range(32):
        words.append(
            (
                words[index]
                ^ sm4_round(words[index + 1] ^ words[index + 2] ^ words[index + 3] ^ round_keys[index])
            ) & 0xffffffff
        )
    return b''.join(word.to_bytes(4, 'big') for word in words[35:31:-1])


def pkcs7_pad(data):
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length]) * pad_length


def mod_inverse(value, modulus):
    return pow(value, -1, modulus)


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % SM2_P == 0:
        return None
    if left == right:
        slope = ((3 * x1 * x1 + SM2_A) * mod_inverse(2 * y1 % SM2_P, SM2_P)) % SM2_P
    else:
        slope = ((y2 - y1) * mod_inverse((x2 - x1) % SM2_P, SM2_P)) % SM2_P
    x3 = (slope * slope - x1 - x2) % SM2_P
    y3 = (slope * (x1 - x3) - y1) % SM2_P
    return x3, y3


def point_multiply(multiplier, point):
    result = None
    addend = point
    while multiplier:
        if multiplier & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        multiplier >>= 1
    return result


def sm2_public_key_from_private(private_key):
    return point_multiply(private_key, (SM2_GX, SM2_GY))


def int_to_32(value):
    return value.to_bytes(32, 'big')


def sm2_compute_message_digest(public_key, data):
    entl = (len(SM2_DEFAULT_ID) * 8).to_bytes(2, 'big')
    x, y = public_key
    za_input = (
        entl
        + SM2_DEFAULT_ID
        + int_to_32(SM2_A)
        + int_to_32(SM2_B)
        + int_to_32(SM2_GX)
        + int_to_32(SM2_GY)
        + int_to_32(x)
        + int_to_32(y)
    )
    return sm3_hash(sm3_hash(za_input) + data)


def der_encode_length(length):
    if length < 0x80:
        return bytes([length])
    data = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(data)]) + data


def der_encode_integer(value):
    data = value.to_bytes((value.bit_length() + 7) // 8 or 1, 'big')
    if data[0] & 0x80:
        data = b'\x00' + data
    return b'\x02' + der_encode_length(len(data)) + data


def der_encode_sequence(*items):
    body = b''.join(items)
    return b'\x30' + der_encode_length(len(body)) + body


def sm2_sign_asn1(private_key_hex, data):
    private_key = int(private_key_hex, 16)
    public_key = sm2_public_key_from_private(private_key)
    digest = sm2_compute_message_digest(public_key, data)
    e = int.from_bytes(digest, 'big')
    while True:
        k = secrets.randbelow(SM2_N - 1) + 1
        x1, _ = point_multiply(k, (SM2_GX, SM2_GY))
        r = (e + x1) % SM2_N
        if r == 0 or r + k == SM2_N:
            continue
        s = (mod_inverse(1 + private_key, SM2_N) * (k - r * private_key)) % SM2_N
        if s:
            return der_encode_sequence(der_encode_integer(r), der_encode_integer(s))
