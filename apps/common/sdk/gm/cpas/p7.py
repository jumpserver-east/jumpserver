# -*- coding: utf-8 -*-
"""
最小 DER / 国密 P7（GM/T 0010 SignedData）解析。

只做登录验签需要的两件事：
1. 从 USBKey 产生的 P7 里取出签名者证书（按 SignerInfo 的 issuerAndSerialNumber 匹配）；
2. 取证书里的 SM2 公钥、序列号、有效期，用来和用户绑定的 UKey 公钥比对。

不依赖 gmssl / cryptography：cryptography 不识别国密 ContentType OID，也不支持 SM2 曲线。
签名本身的验证由加密平台完成，这里不做密码学运算。
"""
import base64
import binascii
import datetime
import hashlib
from dataclasses import dataclass

__all__ = [
    'P7ParseError', 'SignerCertificate', 'load_signer_certificate',
    'normalize_public_key', 'public_key_matches', 'summarize', 'normalize_signed_data',
]

OID_NAMES = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
    '2.5.4.10': 'O', '2.5.4.11': 'OU', '1.2.840.113549.1.9.1': 'E',
}
OID_SM2 = '1.2.156.10197.1.301'            # SM2 算法（曲线）OID，部分 UKey 插件误用在 SignerInfo 上
OID_SM2_SIGN = '1.2.156.10197.1.301.1'     # GM/T 0010 规定的 SignerInfo signatureAlgorithm
OID_SM3_WITH_SM2 = '1.2.156.10197.1.501'   # SM3withSM2，证书签名用


class P7ParseError(ValueError):
    pass


class _Node:
    __slots__ = ('tag', 'value', 'children')

    def __init__(self, tag, value=None, children=None):
        self.tag, self.value, self.children = tag, value, children

    @property
    def constructed(self):
        return self.children is not None


def _parse_one(data, pos):
    try:
        tag = data[pos]
        if tag & 0x1F == 0x1F:
            raise P7ParseError('unsupported multi-byte tag')
        pos += 1
        first = data[pos]
        pos += 1
        if first < 0x80:
            length = first
        else:
            count = first & 0x7F
            if count == 0 or count > 4:
                raise P7ParseError('bad length encoding')
            length = int.from_bytes(data[pos:pos + count], 'big')
            pos += count
    except IndexError:
        raise P7ParseError('truncated DER')
    value = data[pos:pos + length]
    if len(value) != length:
        raise P7ParseError('DER length out of range')
    end = pos + length
    if tag & 0x20:
        children, p = [], 0
        while p < length:
            child, p = _parse_one(value, p)
            children.append(child)
        return _Node(tag, None, children), end
    return _Node(tag, bytes(value), None), end


def _parse(data):
    node, end = _parse_one(data, 0)
    if end != len(data):
        raise P7ParseError('trailing data after DER object')
    return node


def _encode_length(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def _encode(node):
    body = b''.join(_encode(c) for c in node.children) if node.constructed else node.value
    return bytes([node.tag]) + _encode_length(len(body)) + body


def _oid_encode(dotted):
    parts = [int(x) for x in dotted.split('.')]
    out = [40 * parts[0] + parts[1]]
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        out.extend(reversed(chunk))
    return bytes(out)


def _der_int_bytes(value):
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, 'big')
    return b'\x00' + raw if raw[0] & 0x80 else raw


def _oid(raw):
    parts, value = [], 0
    for byte in raw:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            if not parts:
                parts.extend([value // 40, value % 40] if value < 80 else [2, value - 80])
            else:
                parts.append(value)
            value = 0
    return '.'.join(str(x) for x in parts)


def _int(node):
    return int.from_bytes(node.value, 'big', signed=True)


def _dn(node):
    items = []
    for rdn in node.children:
        for atv in rdn.children:
            name = _oid(atv.children[0].value)
            items.append('{}={}'.format(OID_NAMES.get(name, name), atv.children[1].value.decode('utf-8', 'replace')))
    return ','.join(items)


def _time(node):
    text = node.value.decode('ascii')
    if node.tag == 0x17:  # UTCTime
        text = ('20' if int(text[:2]) < 50 else '19') + text
    return datetime.datetime.strptime(text, '%Y%m%d%H%M%SZ').replace(tzinfo=datetime.timezone.utc)


@dataclass
class SignerCertificate:
    der: bytes
    public_key: bytes          # 64 字节 X||Y
    serial_hex: str
    subject: str
    issuer: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    sha256: str
    algorithm: str             # 'SM2' 或公钥算法 OID

    def is_valid_at(self, now=None):
        now = now or datetime.datetime.now(datetime.timezone.utc)
        return self.not_before <= now <= self.not_after


def _certificate(node):
    """解析 X.509 证书 DER 树。"""
    try:
        tbs = node.children[0]
        index = 1 if tbs.children[0].tag == 0xA0 else 0   # [0] EXPLICIT version 可选
        serial = tbs.children[index]
        issuer = tbs.children[index + 2]
        validity = tbs.children[index + 3]
        subject = tbs.children[index + 4]
        spki = tbs.children[index + 5]
        alg = spki.children[0]
        alg_oid = _oid(alg.children[0].value)
        curve = _oid(alg.children[1].value) if len(alg.children) > 1 and alg.children[1].tag == 0x06 else ''
        pub_bits = spki.children[1].value
    except (IndexError, AttributeError):
        raise P7ParseError('unexpected certificate structure')
    if pub_bits[:2] != b'\x00\x04' or len(pub_bits) != 66:
        raise P7ParseError('public key is not an uncompressed 256-bit EC point')
    der = _encode(node)
    return SignerCertificate(
        der=der, public_key=bytes(pub_bits[2:66]), serial_hex=format(_int(serial), 'X'),
        subject=_dn(subject), issuer=_dn(issuer),
        not_before=_time(validity.children[0]), not_after=_time(validity.children[1]),
        sha256=hashlib.sha256(der).hexdigest(),
        algorithm='SM2' if curve == OID_SM2 else (curve or alg_oid),
    )


def load_signer_certificate(p7_der):
    """
    从 PKCS#7 / GM/T 0010 SignedData（DER）中取出签名者证书。

    要求 P7 自带签名者证书（USBKey SOF_SignDataToPKCS7 的默认输出），
    按 SignerInfo.issuerAndSerialNumber 的序列号匹配证书集合。
    """
    if not isinstance(p7_der, (bytes, bytearray)) or not p7_der:
        raise P7ParseError('empty P7')
    try:
        root = _parse(bytes(p7_der))
        if root.tag != 0x30 or len(root.children) != 2 or root.children[1].tag != 0xA0:
            raise P7ParseError('not a ContentInfo structure')
        signed = root.children[1].children[0]
        certs_node = signer_infos = None
        for child in signed.children[3:]:
            if child.tag == 0xA0:
                certs_node = child
            elif child.tag == 0x31:
                signer_infos = child
        if signer_infos is None or not signer_infos.children:
            raise P7ParseError('no SignerInfo')
        if certs_node is None or not certs_node.children:
            raise P7ParseError('P7 does not carry the signer certificate')
        signer_info = signer_infos.children[0]
        issuer_serial = signer_info.children[1]
        signer_serial = _int(issuer_serial.children[1])
        signer_issuer = _dn(issuer_serial.children[0])
    except P7ParseError:
        raise
    except Exception as e:  # noqa: BLE001  任何结构异常都归为解析失败
        raise P7ParseError('invalid P7 structure: {}'.format(e))

    certificates = []
    for cert_node in certs_node.children:
        if cert_node.tag != 0x30:
            continue
        certificates.append(_certificate(cert_node))
    for cert in certificates:
        if int(cert.serial_hex, 16) == signer_serial and cert.issuer == signer_issuer:
            return cert
    for cert in certificates:
        if int(cert.serial_hex, 16) == signer_serial:
            return cert
    raise P7ParseError('signer certificate not found in P7 certificate set')


def normalize_signed_data(p7_der):
    """
    按 GM/T 0010 规范化 SignerInfo，返回 (P7 DER, 变更说明列表)；无需变更时原样返回。

    现场 Windows 版 UKey 插件产出的 P7 把 signatureAlgorithm 写成 SM2 算法 OID 1.2.156.10197.1.301，
    加密平台按该 OID 把签名值当 64 字节裸 r||s 处理，拿到 DER 后密码机报 1015 无效输入；
    Mac 版插件写的是 1.2.156.10197.1.301.1，平台正常验签。这里统一成 .301.1，签名值统一成 DER SEQUENCE{r,s}。
    signatureAlgorithm 和签名值的编码都不在签名覆盖范围内，证书与被签内容一字节不动。
    """
    changes = []
    try:
        root = _parse(bytes(p7_der))
        signed = root.children[1].children[0]
        signer_infos = next(c for c in signed.children[3:] if c.tag == 0x31)
        for signer_info in signer_infos.children:
            rest = signer_info.children[3:]
            if rest and rest[0].tag == 0xA0:
                rest = rest[1:]
            sig_alg, signature = rest[0], rest[1]
            oid = _oid(sig_alg.children[0].value)
            if oid in (OID_SM2, OID_SM3_WITH_SM2):
                sig_alg.children = [_Node(0x06, _oid_encode(OID_SM2_SIGN))] + sig_alg.children[1:]
                changes.append('signatureAlgorithm {} -> {}'.format(oid, OID_SM2_SIGN))
            value = signature.value
            if len(value) == 64 and value[:1] != b'\x30':
                r, s = int.from_bytes(value[:32], 'big'), int.from_bytes(value[32:], 'big')
                signature.value = _encode(_Node(0x30, children=[_Node(0x02, _der_int_bytes(r)), _Node(0x02, _der_int_bytes(s))]))
                changes.append('signature raw r||s -> DER SEQUENCE{r,s}')
    except Exception as e:  # noqa: BLE001  规范化失败就原样发送，由平台给出结论
        return bytes(p7_der), ['normalize skipped: {}: {}'.format(type(e).__name__, e)]
    if not changes:
        return bytes(p7_der), changes
    return _encode(root), changes


def summarize(p7_der):
    """
    P7 结构摘要（不含私密信息），写入审计日志用于定位平台拒绝的原因：
    是否 detached、有无 signedAttrs、证书数量、签名值形态与长度、各 OID。解析失败时返回 error 字段。
    """
    try:
        root = _parse(bytes(p7_der))
        signed = root.children[1].children[0]
        content_info = signed.children[2]
        certs = signer_infos = None
        for child in signed.children[3:]:
            if child.tag == 0xA0:
                certs = child
            elif child.tag == 0x31:
                signer_infos = child
        signer_info = signer_infos.children[0]
        rest = signer_info.children[3:]
        signed_attrs = bool(rest) and rest[0].tag == 0xA0
        if signed_attrs:
            rest = rest[1:]
        sig_alg, signature = rest[0], rest[1]
        return {
            'bytes': len(p7_der),
            'content_type_oid': _oid(root.children[0].value),
            'data_oid': _oid(content_info.children[0].value),
            'detached': len(content_info.children) == 1,
            'certificates': len(certs.children) if certs else 0,
            'signer_infos': len(signer_infos.children),
            'signed_attrs': signed_attrs,
            'digest_algorithm_oid': _oid(signer_info.children[2].children[0].value),
            'signature_algorithm_oid': _oid(sig_alg.children[0].value),
            'signature_bytes': len(signature.value),
            'signature_form': 'der' if signature.value[:1] == b'\x30' else 'raw',
            'sha256': hashlib.sha256(bytes(p7_der)).hexdigest(),
        }
    except Exception as e:  # noqa: BLE001  摘要只用于诊断，任何异常都不能影响登录流程
        return {'error': '{}: {}'.format(type(e).__name__, e)}


def normalize_public_key(value):
    """
    把用户绑定时保存的 UKey 公钥统一成 64 字节 X||Y。

    兼容：Base64 或 HEX 文本；裸 X||Y（64 字节）、带 0x04 前缀的非压缩点（65 字节）、
    DER SubjectPublicKeyInfo（BIT STRING 内 00 04 X Y）。
    """
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if not (64 <= len(raw) <= 128) or raw[:1] not in (b'\x04', b'\x30') and len(raw) != 64:
            raw = _decode_text(raw.decode('ascii', 'ignore'))
    else:
        raw = _decode_text(str(value))
    if len(raw) == 64:
        return raw
    if len(raw) == 65 and raw[0] == 0x04:
        return raw[1:]
    marker = raw.find(b'\x03\x42\x00\x04')
    if marker >= 0 and len(raw) >= marker + 4 + 64:
        return raw[marker + 4:marker + 4 + 64]
    raise ValueError('unrecognized public key format ({} bytes)'.format(len(raw)))


def _decode_text(text):
    text = ''.join(text.split())
    if text.startswith('-----BEGIN'):
        text = ''.join(line for line in text.splitlines() if not line.startswith('-----'))
    try:
        if len(text) in (128, 130, 182) and all(c in '0123456789abcdefABCDEF' for c in text):
            return bytes.fromhex(text)
    except ValueError:
        pass
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        pass
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise ValueError('public key is neither base64 nor hex')


def public_key_matches(bound_public_key, certificate):
    """用户绑定的公钥是否与 P7 签名者证书公钥一致。"""
    try:
        return normalize_public_key(bound_public_key) == certificate.public_key
    except ValueError:
        return False
