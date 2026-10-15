# -*- coding: utf-8 -*-
"""
CPAS U013 客户端与 P7 解析的单元测试，不依赖 Django 和网络。

运行方式（任选）：
  cd apps && python -m unittest common.sdk.gm.cpas.tests
  cd apps/common/sdk/gm && python -m unittest cpas.tests

样本为 2026-10-14 USBKey 真实签名的 detached 国密 P7（只带用户证书的裁剪版）及配套用户证书，
与现场 U013 联调通过的材料同一批次。
"""
import base64
import binascii
import json
import unittest
from unittest import mock

from .client import CPASClient, CPASConfigError, CPASError, CPASTransportError
from .p7 import (
    P7ParseError, load_signer_certificate, normalize_public_key, public_key_matches,
    normalize_signed_data, summarize, OID_SM2, OID_SM2_SIGN, _parse, _encode, _oid_encode, _Node,
)

# ===== SAMPLE-BEGIN =====
SAMPLE_MESSAGE = 'JumpServer-U013-12226002C56B29EE706EC6C1BFEEE2F6C7B6CE589D980AAF'
USER_CERT_BASE64 = 'MIIB7zCCAZOgAwIBAgIGAaEt6+U1MAwGCCqBHM9VAYN1BQAwSzELMAkGA1UEBhMCQ04xDjAMBgNVBAoTBUdNU1NMMRAwDgYDVQQLEwdQS0kvU00yMRowGAYDVQQDExFNaWRkbGVDQSBmb3IgVGVzdDAiGA8yMDI2MTAxMTE2MDAwMFoYDzIwMzYxMDExMTYwMDAwWjAeMQswCQYDVQQGEwJDTjEPMA0GA1UEAwwG5byg5LiJMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAETmB8dVvDB5Vf7MVHnrj8brvWPLDkawVWMk4bCD5TQfDd4bX5dSQ2Z8Kt6bmjPM5RIZUFiEeO3+O6CyylZsXS0KOBiTCBhjAbBgNVHSMEFDASgBD5f1W0J5QzYqZWym/MXRr/MBkGA1UdDgQSBBDAkMaj8usDmCVT/lXfmI/+MDEGCCsGAQUFBwEBBCUwIzAhBggrBgEFBQcwAYYVaHR0cHM6Ly9vY3NwLmdtc3NsLmNuMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgDAMAwGCCqBHM9VAYN1BQADSAAwRQIgF33NxlulUK9165Mj5aFA/EsE8TS2aYk0EI9az+LuifgCIQCjvlql71BnnkfV/denv4YvHhHzYONk0DxktZ7T5qhBBQ=='
USER_PUBLIC_KEY_HEX = '4e607c755bc307955fecc5479eb8fc6ebbd63cb0e46b0556324e1b083e5341f0dde1b5f975243667c2ade9b9a33cce5121950588478edfe3ba0b2ca566c5d2d0'
SAMPLE_P7_BASE64 = 'MIIC7gYKKoEcz1UGAQQCAqCCAt4wggLaAgEBMQ4wDAYIKoEcz1UBgxEFADAMBgoqgRzPVQYBBAIBoIIB8zCCAe8wggGToAMCAQICBgGhLevlNTAMBggqgRzPVQGDdQUAMEsxCzAJBgNVBAYTAkNOMQ4wDAYDVQQKEwVHTVNTTDEQMA4GA1UECxMHUEtJL1NNMjEaMBgGA1UEAxMRTWlkZGxlQ0EgZm9yIFRlc3QwIhgPMjAyNjEwMTExNjAwMDBaGA8yMDM2MTAxMTE2MDAwMFowHjELMAkGA1UEBhMCQ04xDzANBgNVBAMMBuW8oOS4iTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABE5gfHVbwweVX+zFR564/G671jyw5GsFVjJOGwg+U0Hw3eG1+XUkNmfCrem5ozzOUSGVBYhHjt/jugsspWbF0tCjgYkwgYYwGwYDVR0jBBQwEoAQ+X9VtCeUM2KmVspvzF0a/zAZBgNVHQ4EEgQQwJDGo/LrA5glU/5V35iP/jAxBggrBgEFBQcBAQQlMCMwIQYIKwYBBQUHMAGGFWh0dHBzOi8vb2NzcC5nbXNzbC5jbjAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIAwDAMBggqgRzPVQGDdQUAA0gAMEUCIBd9zcZbpVCvdeuTI+WhQPxLBPE0tmmJNBCPWs/i7on4AiEAo75ape9QZ55H1f3Xp7+GLx4R82DjZNA8ZLWe0+aoQQUxgb8wgbwCAQEwVTBLMQswCQYDVQQGEwJDTjEOMAwGA1UEChMFR01TU0wxEDAOBgNVBAsTB1BLSS9TTTIxGjAYBgNVBAMTEU1pZGRsZUNBIGZvciBUZXN0AgYBoS3r5TUwCgYIKoEcz1UBgxEwCwYJKoEcz1UBgi0BBEcwRQIgH8QeC1ck6LfPvVedBEiX8LX3UNaDI2zW/0q9qEUBl6QCIQCYmQ1MmoZALa5LVui4nBU1mRJwz2kbxNaSlGuLtpyMlA=='
# ===== SAMPLE-END =====


def _ok_response(**extra):
    document = {'responseCode': 0, 'userDN': '', 'serialNum': '', 'issuserDN': '',
                'startTime': '', 'endTime': '', 'algorithmID': ''}
    document.update(extra)
    return 200, json.dumps(document, ensure_ascii=False)


class FakeTransport:
    def __init__(self, status=200, text=None, exc=None):
        self.status, self.text, self.exc = status, text, exc
        self.calls = []

    def __call__(self, url, body):
        self.calls.append((url, body))
        if self.exc:
            raise self.exc
        return self.status, self.text


def make_client(**kwargs):
    params = dict(url='http://cpas.test/cpas/apiServ/bigData', biz_sys_id='jumpserver',
                  cert_name='jumpserver_MiddleCA.cer', cert_app='DC', user_id='1234567812345678')
    params.update(kwargs)
    return CPASClient(**params)


class P7Tests(unittest.TestCase):
    def setUp(self):
        self.p7 = base64.b64decode(SAMPLE_P7_BASE64)
        self.cert = base64.b64decode(USER_CERT_BASE64)

    def test_load_signer_certificate(self):
        signer = load_signer_certificate(self.p7)
        self.assertEqual(signer.der, self.cert)
        self.assertEqual(signer.public_key.hex(), USER_PUBLIC_KEY_HEX)
        self.assertEqual(signer.serial_hex, '1A12DEBE535')
        self.assertIn('CN=张三', signer.subject)
        self.assertIn('MiddleCA for Test', signer.issuer)
        self.assertEqual(signer.algorithm, 'SM2')
        self.assertEqual(signer.not_before.year, 2026)
        self.assertEqual(signer.not_after.year, 2036)

    def test_rejects_garbage(self):
        for bad in (b'', b'\x30\x03\x02\x01', b'not der at all', self.cert):
            with self.assertRaises(P7ParseError):
                load_signer_certificate(bad)

    @staticmethod
    def _signer_parts(tree):
        signed = tree.children[1].children[0]
        signer_info = next(c for c in signed.children[3:] if c.tag == 0x31).children[0]
        rest = signer_info.children[3:]
        if rest and rest[0].tag == 0xA0:
            rest = rest[1:]
        return rest[0], rest[1]

    def test_normalize_windows_plugin_oid(self):
        # Windows 版插件：signatureAlgorithm 写成 1.2.156.10197.1.301，规范化后应与 Mac 版产出逐字节一致
        tree = _parse(self.p7)
        sig_alg, _ = self._signer_parts(tree)
        sig_alg.children = [_Node(0x06, _oid_encode(OID_SM2))]
        windows_style = _encode(tree)
        self.assertEqual(summarize(windows_style)['signature_algorithm_oid'], OID_SM2)
        normalized, changes = normalize_signed_data(windows_style)
        self.assertEqual(normalized, self.p7)
        self.assertEqual(len(changes), 1)
        self.assertIn(OID_SM2_SIGN, changes[0])

    def test_normalize_raw_signature(self):
        tree = _parse(self.p7)
        _, signature = self._signer_parts(tree)
        seq = _parse(signature.value)
        r = int.from_bytes(seq.children[0].value, 'big', signed=True)
        s = int.from_bytes(seq.children[1].value, 'big', signed=True)
        signature.value = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        raw_style = _encode(tree)
        self.assertEqual(summarize(raw_style)['signature_form'], 'raw')
        normalized, changes = normalize_signed_data(raw_style)
        self.assertEqual(normalized, self.p7)
        self.assertEqual(len(changes), 1)

    def test_normalize_already_standard(self):
        normalized, changes = normalize_signed_data(self.p7)
        self.assertEqual(normalized, self.p7)
        self.assertEqual(changes, [])
        self.assertEqual(normalize_signed_data(b'garbage')[0], b'garbage')

    def test_summarize(self):
        info = summarize(self.p7)
        self.assertTrue(info['detached'])
        self.assertFalse(info['signed_attrs'])
        self.assertEqual(info['certificates'], 1)
        self.assertEqual(info['signature_form'], 'der')
        self.assertEqual(info['signature_algorithm_oid'], OID_SM2_SIGN)
        self.assertIn('error', summarize(b'garbage'))

    def test_rejects_p7_without_certificates(self):
        # 把证书集合 [0] 整体删掉后应报“未携带签名者证书”
        tree = _parse(self.p7)
        signed = tree.children[1].children[0]
        signed.children = [c for c in signed.children if c.tag != 0xA0]
        with self.assertRaises(P7ParseError):
            load_signer_certificate(_encode(tree))

    def test_normalize_public_key_formats(self):
        raw = bytes.fromhex(USER_PUBLIC_KEY_HEX)
        self.assertEqual(normalize_public_key(base64.b64encode(raw).decode()), raw)
        self.assertEqual(normalize_public_key(base64.b64encode(b'\x04' + raw).decode()), raw)
        self.assertEqual(normalize_public_key(raw.hex()), raw)
        self.assertEqual(normalize_public_key(raw.hex().upper()), raw)
        self.assertEqual(normalize_public_key('04' + raw.hex()), raw)
        self.assertEqual(normalize_public_key(raw), raw)
        # DER SubjectPublicKeyInfo（证书内的公钥结构）
        spki_index = self.cert.find(b'\x03\x42\x00\x04')
        spki = self.cert[spki_index - 25:spki_index + 68]
        self.assertEqual(normalize_public_key(base64.b64encode(spki).decode()), raw)
        with self.assertRaises(ValueError):
            normalize_public_key('zz')

    def test_public_key_matches(self):
        signer = load_signer_certificate(self.p7)
        raw = bytes.fromhex(USER_PUBLIC_KEY_HEX)
        self.assertTrue(public_key_matches(base64.b64encode(raw).decode(), signer))
        other = bytes([raw[0] ^ 1]) + raw[1:]
        self.assertFalse(public_key_matches(base64.b64encode(other).decode(), signer))
        self.assertFalse(public_key_matches('', signer))


class ClientBuildTests(unittest.TestCase):
    def test_business_data_encoding(self):
        client = make_client()
        p7 = base64.b64decode(SAMPLE_P7_BASE64)
        message = SAMPLE_MESSAGE.encode('ascii')
        business = client.build_u013_business_data(message, p7)
        self.assertEqual(business['certName'], 'jumpserver_MiddleCA.cer')
        self.assertEqual(business['certApp'], 'DC')
        self.assertEqual(business['flag'], '0')
        self.assertIs(business['hashID'], 0)
        self.assertEqual(business['algorithmID'], '2')
        self.assertEqual(business['userID'], '1234567812345678')
        self.assertEqual(business['dataType'], '1')
        self.assertEqual(business['signType'], '3')
        # 外层 Base64 解开后：data 是原文大写 HEX 文本，sign 是 P7 的 Base64 文本
        data_text = base64.b64decode(business['data'])
        self.assertEqual(data_text, binascii.hexlify(message).upper())
        self.assertEqual(bytes.fromhex(data_text.decode()), message)
        sign_text = base64.b64decode(business['sign'])
        self.assertEqual(base64.b64decode(sign_text), p7)
        self.assertNotIn('pkCert', business)

    def test_user_id_omitted_when_empty(self):
        business = make_client(user_id='').build_u013_business_data(b'abc', base64.b64decode(SAMPLE_P7_BASE64))
        self.assertNotIn('userID', business)

    def test_request_envelope(self):
        client = make_client(class_type=0, svc_code_prefix='serv', svc_code_num=0)
        request = client.build_request({'x': 1}, serial_no='abc')
        self.assertEqual(request, {
            'serialNo': 'abc', 'bizSysId': 'jumpserver', 'svcCode': 'U013', 'classType': 0,
            'svcCodePrefix': 'serv', 'svcCodeNum': 0, 'businessData': {'x': 1},
        })

    def test_invalid_inputs(self):
        client = make_client()
        with self.assertRaises(ValueError):
            client.build_u013_business_data(b'', b'\x30')
        with self.assertRaises(ValueError):
            client.build_u013_business_data(b'abc', b'not der')

    def test_from_settings(self):
        fake = mock.Mock(CPAS_URL=' http://x/cpas/apiServ/bigData ', CPAS_BIZ_SYS_ID='sys', CPAS_UKEY_CERT_NAME='ca.cer',
                         CPAS_UKEY_CERT_APP='DC', CPAS_UKEY_USER_ID='1234567812345678', CPAS_CLASS_TYPE=0,
                         CPAS_SVC_CODE_PREFIX='serv', CPAS_SVC_CODE_NUM=0, CPAS_CONNECT_TIMEOUT=3,
                         CPAS_READ_TIMEOUT=7, CPAS_VERIFY_SSL=False)
        client = CPASClient.from_settings(fake)
        self.assertEqual(client.url, 'http://x/cpas/apiServ/bigData')
        self.assertEqual(client.biz_sys_id, 'sys')
        self.assertEqual(client.connect_timeout, 3.0)
        self.assertEqual(client.read_timeout, 7.0)
        self.assertFalse(client.verify_ssl)


class ClientVerifyTests(unittest.TestCase):
    def setUp(self):
        self.p7 = base64.b64decode(SAMPLE_P7_BASE64)
        self.message = SAMPLE_MESSAGE.encode('ascii')

    def test_success(self):
        transport = FakeTransport(*_ok_response())
        client = make_client(transport=transport)
        result = client.verify_u013(self.message, self.p7)
        self.assertEqual(result.code, 0)
        self.assertEqual(len(result.serial_no), 32)
        url, body = transport.calls[0]
        request = json.loads(body)
        self.assertEqual(request['serialNo'], result.serial_no)
        self.assertEqual(request['svcCode'], 'U013')
        self.assertEqual(request['businessData']['dataType'], '1')

    def test_string_response_code_is_tolerated(self):
        transport = FakeTransport(*_ok_response(responseCode='0'))
        self.assertEqual(make_client(transport=transport).verify_u013(self.message, self.p7).code, 0)

    def test_rejected(self):
        text = json.dumps({'responseCode': 1001, 'responseRemark': 'HSM:确认错误。输入密钥奇偶校验错误警告'}, ensure_ascii=False)
        transport = FakeTransport(200, text)
        with self.assertRaises(CPASError) as ctx:
            make_client(transport=transport).verify_u013(self.message, self.p7)
        self.assertEqual(ctx.exception.code, 1001)
        self.assertIn('奇偶', ctx.exception.remark)
        self.assertEqual(len(ctx.exception.serial_no), 32)
        self.assertNotIsInstance(ctx.exception, CPASTransportError)

    def test_missing_field_code(self):
        text = json.dumps({'responseRemark': '[certName] in field [body/certName] does not exist', 'responseCode': 10014})
        with self.assertRaises(CPASError) as ctx:
            make_client(transport=FakeTransport(200, text)).verify_u013(self.message, self.p7)
        self.assertEqual(ctx.exception.code, 10014)

    def test_http_error(self):
        with self.assertRaises(CPASTransportError):
            make_client(transport=FakeTransport(502, '<html>bad gateway</html>')).verify_u013(self.message, self.p7)

    def test_non_json(self):
        with self.assertRaises(CPASTransportError):
            make_client(transport=FakeTransport(200, 'ok')).verify_u013(self.message, self.p7)

    def test_missing_code(self):
        with self.assertRaises(CPASTransportError):
            make_client(transport=FakeTransport(200, '{"foo": 1}')).verify_u013(self.message, self.p7)

    def test_network_exception(self):
        with self.assertRaises(CPASTransportError) as ctx:
            make_client(transport=FakeTransport(exc=OSError('timed out'))).verify_u013(self.message, self.p7)
        self.assertIn('timed out', str(ctx.exception))

    def test_config_missing(self):
        for missing in ('url', 'biz_sys_id', 'cert_name'):
            client = make_client(transport=FakeTransport(*_ok_response()), **{missing: ''})
            with self.assertRaises(CPASConfigError):
                client.verify_u013(self.message, self.p7)
        with self.assertRaises(CPASConfigError):
            make_client(url='cpas.test/bigData', transport=FakeTransport(*_ok_response())).verify_u013(self.message, self.p7)


if __name__ == '__main__':
    unittest.main()
