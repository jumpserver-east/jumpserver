# -*- coding: utf-8 -*-
"""
加密平台 CPAS HTTP 接口（/cpas/apiServ/bigData）的 U013 数字签名核签客户端。

报文格式依据《加密平台CPAS接入手册 V3.7.9》2.2.3.1 和《UAS 安全服务接口文档》4.2.4，
参数取值依据 2026-10-15 现场联调通过的组合（见 u013-matrix 报告）：
  - data：原文的大写 HEX 文本，dataType=1。dataType=0/3 在该平台会被密码机判验签失败。
  - sign：USBKey 产生的 detached 国密 P7（DER）的 Base64 文本，signType=3，P7 自带签名者证书。
  - certName：用户证书直接签发 CA 在平台 certApp 下的记录名（平台只做一级校验）。
  - 所有 Java byte[] 入参在 JSON 里都是其字节的 Base64 字符串（CPAS 按 Fastjson 默认规则解码）。
"""
import base64
import binascii
import json
import logging
import time
import uuid
from dataclasses import dataclass, field

__all__ = ['CPASClient', 'CPASError', 'CPASConfigError', 'CPASTransportError', 'U013Result']

logger = logging.getLogger(__name__)

SVC_CODE_U013 = 'U013'
DEFAULT_HEADERS = {'Content-Type': 'application/json; charset=utf-8'}
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class CPASError(Exception):
    """平台返回非 0 响应码，或请求无法完成。"""

    def __init__(self, message, code=None, remark=None, serial_no=None, request=None):
        super().__init__(message)
        self.code = code
        self.remark = remark
        self.serial_no = serial_no
        self.request = request

    def __str__(self):
        parts = [super().__str__()]
        if self.code is not None:
            parts.append('code={}'.format(self.code))
        if self.remark:
            parts.append('remark={}'.format(self.remark))
        if self.serial_no:
            parts.append('serialNo={}'.format(self.serial_no))
        return ' '.join(parts)


class CPASConfigError(CPASError):
    """CPAS_* 配置缺失或非法。"""


class CPASTransportError(CPASError):
    """网络错误、HTTP 非 200 或响应不是 JSON。"""


@dataclass
class U013Result:
    serial_no: str
    code: int
    remark: str = ''
    data: dict = field(default_factory=dict)          # 响应 JSON
    request: dict = field(default_factory=dict)       # 发出的完整请求报文（取证用）
    http_status: int = 0
    response_text: str = ''
    elapsed_ms: int = 0


def _as_bytes(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return str(value).encode('utf-8')


def _wire(raw):
    """JSON 传输层：Java byte[] -> Base64 字符串。"""
    return base64.b64encode(raw).decode('ascii')


class CPASClient:
    def __init__(self, url, biz_sys_id, cert_name, cert_app='DC', user_id='1234567812345678',
                 class_type=0, svc_code_prefix='serv', svc_code_num=0,
                 connect_timeout=5, read_timeout=10, verify_ssl=True, transport=None):
        self.url = (url or '').strip()
        self.biz_sys_id = (biz_sys_id or '').strip()
        self.cert_name = (cert_name or '').strip()
        self.cert_app = (cert_app or 'DC').strip()
        self.user_id = (user_id or '').strip()
        self.class_type = int(class_type or 0)
        self.svc_code_prefix = (svc_code_prefix or 'serv').strip()
        self.svc_code_num = int(svc_code_num or 0)
        self.connect_timeout = float(connect_timeout or 5)
        self.read_timeout = float(read_timeout or 10)
        self.verify_ssl = bool(verify_ssl)
        self._transport = transport or self._requests_transport

    @classmethod
    def from_settings(cls, settings=None, **overrides):
        """按 config.yml 的 CPAS_* 配置构造客户端。"""
        if settings is None:
            from django.conf import settings as django_settings
            settings = django_settings
        params = dict(
            url=getattr(settings, 'CPAS_URL', ''),
            biz_sys_id=getattr(settings, 'CPAS_BIZ_SYS_ID', ''),
            cert_name=getattr(settings, 'CPAS_UKEY_CERT_NAME', ''),
            cert_app=getattr(settings, 'CPAS_UKEY_CERT_APP', 'DC'),
            user_id=getattr(settings, 'CPAS_UKEY_USER_ID', '1234567812345678'),
            class_type=getattr(settings, 'CPAS_CLASS_TYPE', 0),
            svc_code_prefix=getattr(settings, 'CPAS_SVC_CODE_PREFIX', 'serv'),
            svc_code_num=getattr(settings, 'CPAS_SVC_CODE_NUM', 0),
            connect_timeout=getattr(settings, 'CPAS_CONNECT_TIMEOUT', 5),
            read_timeout=getattr(settings, 'CPAS_READ_TIMEOUT', 10),
            verify_ssl=getattr(settings, 'CPAS_VERIFY_SSL', True),
        )
        params.update(overrides)
        return cls(**params)

    def check_config(self):
        missing = [name for name, value in (
            ('CPAS_URL', self.url), ('CPAS_BIZ_SYS_ID', self.biz_sys_id), ('CPAS_UKEY_CERT_NAME', self.cert_name),
        ) if not value]
        if missing:
            raise CPASConfigError('CPAS config missing: {}'.format(', '.join(missing)))
        if not self.url.lower().startswith(('http://', 'https://')):
            raise CPASConfigError('CPAS_URL must be an http(s) URL')

    # ── 报文 ────────────────────────────────────────────────────────────────

    def build_u013_business_data(self, message, p7_der):
        """
        U013 入参。message 为签名原文（UKey 实际签名的字节），p7_der 为 detached 国密 P7 DER。
        """
        message = _as_bytes(message)
        p7_der = _as_bytes(p7_der)
        if not message:
            raise ValueError('message is empty')
        if not p7_der or p7_der[:1] != b'\x30':
            raise ValueError('p7_der is not DER encoded')
        business = {
            'certName': self.cert_name,
            'certApp': self.cert_app,
            'flag': '0',                       # detached
            'hashID': 0,                       # 内部做摘要（Integer）
            'algorithmID': '2',                # SM3WithSM2
            'dataType': '1',                   # data 为 HEX 文本
            'data': _wire(binascii.hexlify(message).upper()),
            'signType': '3',                   # sign 为 Base64 文本
            'sign': _wire(base64.b64encode(p7_der)),
        }
        if self.user_id:
            business['userID'] = self.user_id
        return business

    def build_request(self, business_data, serial_no=None):
        return {
            'serialNo': serial_no or uuid.uuid4().hex,
            'bizSysId': self.biz_sys_id,
            'svcCode': SVC_CODE_U013,
            'classType': self.class_type,
            'svcCodePrefix': self.svc_code_prefix,
            'svcCodeNum': self.svc_code_num,
            'businessData': business_data,
        }

    # ── 调用 ────────────────────────────────────────────────────────────────

    def verify_u013(self, message, p7_der):
        """
        调用 U013 核签。成功返回 U013Result（code == 0）；
        平台拒绝抛 CPASError（带 code/remark/serialNo），请求失败抛 CPASTransportError。
        """
        self.check_config()
        request = self.build_request(self.build_u013_business_data(message, p7_der))
        serial_no = request['serialNo']
        body = json.dumps(request).encode('utf-8')
        started = time.monotonic()
        try:
            status, text = self._transport(self.url, body)
        except CPASError:
            raise
        except Exception as e:  # noqa: BLE001  网络层任何异常都按传输错误处理
            logger.error('CPAS U013 request failed: serialNo=%s error=%s', serial_no, e)
            raise CPASTransportError('CPAS request failed: {}'.format(e), serial_no=serial_no, request=request)
        elapsed_ms = round((time.monotonic() - started) * 1000)

        try:
            document = json.loads(text)
        except (TypeError, ValueError):
            logger.error('CPAS U013 non-JSON response: serialNo=%s http=%s body=%r', serial_no, status, text[:500])
            raise CPASTransportError('CPAS response is not JSON', code=None, remark=text[:200], serial_no=serial_no, request=request)
        if not isinstance(document, dict):
            raise CPASTransportError('CPAS response is not an object', serial_no=serial_no, request=request)
        code = document.get('responseCode')
        remark = document.get('responseRemark')
        remark = '' if remark is None else str(remark)
        if isinstance(code, str) and code.strip().lstrip('-').isdigit():
            code = int(code.strip())
        if status != 200:
            logger.error('CPAS U013 HTTP %s: serialNo=%s code=%s remark=%s', status, serial_no, code, remark)
            raise CPASTransportError('CPAS HTTP {}'.format(status), code=code, remark=remark, serial_no=serial_no, request=request)
        if not isinstance(code, int):
            raise CPASTransportError('CPAS responseCode missing or invalid', code=code, remark=remark, serial_no=serial_no, request=request)
        if code != 0:
            logger.warning('CPAS U013 rejected: serialNo=%s code=%s remark=%s', serial_no, code, remark)
            raise CPASError('CPAS U013 verify failed', code=code, remark=remark, serial_no=serial_no, request=request)
        return U013Result(serial_no=serial_no, code=0, remark=remark, data=document, request=request,
                          http_status=status, response_text=text, elapsed_ms=elapsed_ms)

    def _requests_transport(self, url, body):
        import requests  # JumpServer 自带；延迟导入便于无 Django/requests 环境下跑单元测试

        response = requests.post(
            url, data=body, headers=DEFAULT_HEADERS,
            timeout=(self.connect_timeout, self.read_timeout), verify=self.verify_ssl,
        )
        content = response.content[:MAX_RESPONSE_BYTES]
        return response.status_code, content.decode('utf-8-sig', errors='replace')
