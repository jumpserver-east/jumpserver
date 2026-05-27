#!/usr/bin/env python3
import argparse
import base64
import binascii
import hashlib
import json
import math
import secrets
import struct
import sys
import time
import zlib
from urllib import error as url_error
from urllib import request as url_request

TOKEN_URL = '/openapi/resource/getAccessToken'
COMPARE_URL = '/openapi/face/compare'
JSON_TYPE = 'application/json;charset=UTF-8'

AI_FACE_BASE_URL = 'http://localhost:18080'
AI_FACE_APP_ID = '6435e616f311b23dd6561980ebd'
AI_FACE_SIGN_KEY = '0309540920CA56551A7D169E413220925C463922898D'
AI_FACE_SM4_KEY = 'e2e2d245a5b84fc48dc4e5dd6181cdc8'
AI_FACE_ACCESS_TOKEN = ''
AI_FACE_PASS_THRESHOLD = 0.8

# 两张内置合成头像 PNG。它们不是真人照片，只用于调试 fileA/fileB 入参、签名、加密和请求链路。
FAKE_FACE_SIZE = 256


def mask(value, left=6, right=4):
    if value is None:
        return ''
    text = str(value)
    if len(text) <= left + right:
        return '*' * len(text)
    return '{}{}{}'.format(text[:left], '*' * (len(text) - left - right), text[-right:])


def step(title):
    print('\n=== {} ==='.format(title), flush=True)


def compact_json(data):
    return json.dumps(data, ensure_ascii=False, separators=(',', ':'))


def pretty_json(data):
    return json.dumps(data, ensure_ascii=False, indent=2)


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
        next_key = key_state[index] ^ sm4_key_round(key_state[index + 1] ^ key_state[index + 2] ^ key_state[index + 3] ^ SM4_CK[index])
        next_key &= 0xffffffff
        key_state.append(next_key)
        round_keys.append(next_key)
    return round_keys


def sm4_encrypt_block(block, round_keys):
    words = bytes_to_words(block)
    for index in range(32):
        words.append((words[index] ^ sm4_round(words[index + 1] ^ words[index + 2] ^ words[index + 3] ^ round_keys[index])) & 0xffffffff)
    return b''.join(word.to_bytes(4, 'big') for word in words[35:31:-1])


def pkcs7_pad(data):
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length]) * pad_length


SM2_P = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
SM2_A = 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc
SM2_B = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93
SM2_N = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123
SM2_GX = 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7
SM2_GY = 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0
SM2_DEFAULT_ID = b'1234567812345678'


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


def png_chunk(kind, data):
    return (
        struct.pack('>I', len(data))
        + kind
        + data
        + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    )


def fake_face_image_base64(variant):
    width = FAKE_FACE_SIZE
    height = FAKE_FACE_SIZE
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            distance = math.sqrt((x - width / 2) ** 2 + (y - height / 2) ** 2) / (width / 1.4)
            base = int(236 - 36 * min(distance, 1))
            r, g, b = base, base + 6, base + 10

            sx = (x - width / 2) / (width / 2)
            if y > 168 and abs(sx) < 0.58 + (y - 168) / 120:
                r, g, b = ((52, 84, 112), (92, 76, 126))[variant]
            if 90 < x < 166 and 136 < y < 190:
                r, g, b = ((214, 168, 137), (183, 139, 112))[variant]

            cx, cy = width / 2, 95
            rx, ry = ((54, 68), (50, 66))[variant]
            if ((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2 <= 1:
                shade = int(10 * math.sin((x + variant * 17) / 16) + 8 * math.cos(y / 19))
                skin = ((224, 176, 143), (192, 145, 117))[variant]
                r, g, b = skin[0] + shade, skin[1] + shade // 2, skin[2] + shade // 3
            if ((x - cx) / 58) ** 2 + ((y - 66) / 47) ** 2 <= 1 and y < 88 + 0.25 * abs(x - cx):
                r, g, b = ((48, 35, 30), (28, 29, 34))[variant]
            if variant == 1 and 70 < y < 138 and (70 < x < 86 or 170 < x < 187):
                r, g, b = 26, 27, 31

            eye_y = 92 if variant == 0 else 94
            for ex in ((106, 150), (108, 148))[variant]:
                if ((x - ex) / 8) ** 2 + ((y - eye_y) / 4.5) ** 2 <= 1:
                    r, g, b = 32, 30, 28
                if ((x - (ex + 2)) / 2.3) ** 2 + ((y - (eye_y - 1)) / 1.7) ** 2 <= 1:
                    r, g, b = 238, 238, 232
                brow_y = eye_y - 13
                tilt = -0.08 if ex < 128 else 0.08
                if abs(y - (brow_y + (x - ex) * tilt)) < 2 and abs(x - ex) < 13:
                    r, g, b = 42, 32, 28

            if abs(x - cx) < 5 and 96 < y < 123:
                r, g, b = ((196, 142, 116), (165, 117, 95))[variant]
            if ((x - (cx - 4)) / 5) ** 2 + ((y - 124) / 3) ** 2 <= 1:
                r, g, b = ((154, 99, 85), (126, 83, 72))[variant]
            if ((x - (cx + 5)) / 5) ** 2 + ((y - 124) / 3) ** 2 <= 1:
                r, g, b = ((154, 99, 85), (126, 83, 72))[variant]

            mouth_y = 140 if variant == 0 else 138
            if ((x - cx) / 20) ** 2 + ((y - mouth_y) / 6) ** 2 <= 1 and y > mouth_y - 3:
                r, g, b = ((146, 66, 72), (125, 56, 66))[variant]
            if ((x - cx) / 15) ** 2 + ((y - (mouth_y - 1)) / 2.2) ** 2 <= 1:
                r, g, b = 225, 190, 184

            noise = ((x * 17 + y * 31 + variant * 43) % 11) - 5
            row.extend(max(0, min(255, channel + noise)) for channel in (r, g, b))
        rows.append(b'\x00' + bytes(row))

    raw = b''.join(rows)
    png = (
        b'\x89PNG\r\n\x1a\n'
        + png_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
        + png_chunk(b'IDAT', zlib.compress(raw, 9))
        + png_chunk(b'IEND', b'')
    )
    return base64.b64encode(png).decode('ascii')


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
        description='Complete AI face platform test: get accessToken, then compare two fake face images.'
    )
    parser.add_argument('--seq', default='debug-fake-image-compare', help='request sequence value')
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('--sign-key', default=AI_FACE_SIGN_KEY, help='64-char SM2 private key hex')
    parser.add_argument('--sm4-key', default=AI_FACE_SM4_KEY, help='32-char SM4 key hex')
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
        self.sign_key = args.sign_key
        self.sm4_key = args.sm4_key
        self.access_token = AI_FACE_ACCESS_TOKEN
        self.threshold = AI_FACE_PASS_THRESHOLD
        self.timeout = args.timeout

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
            raise RuntimeError('missing config: {}'.format(', '.join(missing)))
        self.validate_hex_key('AI_FACE_SIGN_KEY', self.sign_key, 64)
        self.validate_hex_key('AI_FACE_SM4_KEY', self.sm4_key, 32)

    @staticmethod
    def validate_hex_key(name, value, expected_length):
        if len(value) != expected_length or any(c not in '0123456789abcdefABCDEF' for c in value):
            raise RuntimeError('{} must be a {}-char hex string'.format(name, expected_length))

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
            'fileA': self.encrypt_fake_image_base64('fileA', 0),
            'fileB': self.encrypt_fake_image_base64('fileB', 1),
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
        sm3_hex = sm3_hash(request_body.encode('utf-8')).hex().upper()
        print('SM3(request body): {}'.format(sm3_hex))
        sign = sm2_sign_asn1(self.sign_key, sm3_hex.encode('utf-8')).hex().upper()
        print('SM2 sign: {}'.format(mask(sign, 12, 12)))
        return sign

    def encrypt_fake_image_base64(self, label, variant):
        image_base64 = fake_face_image_base64(variant)
        content = base64.b64decode(image_base64)
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
        key = binascii.unhexlify(self.sm4_key)
        round_keys = sm4_round_keys(key)
        encrypted = b''.join(
            sm4_encrypt_block(block, round_keys)
            for block in chunks(pkcs7_pad(text.encode('utf-8')), 16)
        )
        return encrypted.hex().upper()

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
        print('crypto: pure Python SM2/SM3/SM4')
        print('threshold: {}'.format(client.threshold))
        for label, variant in [('fake face A sha256', 0), ('fake face B sha256', 1)]:
            print('{}: {}'.format(
                label,
                hashlib.sha256(base64.b64decode(fake_face_image_base64(variant))).hexdigest()
            ))

        step('1. 获取访问令牌')
        if client.access_token:
            print('using configured access token: {}'.format(mask(client.access_token, 10, 6)))
        else:
            client.get_access_token()

        if args.token_only:
            return 0

        step('2. 人脸 1:1 比对（fileA/fileB 使用两张内置假人脸图）')
        client.compare(args.seq)
        return 0
    except Exception as exc:
        print('\nERROR: {}'.format(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
