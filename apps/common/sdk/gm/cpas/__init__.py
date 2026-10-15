"""
加密平台 CPAS（科友 UAS U013）验签 SDK。

UKey 登录时不在本地（piico 密码卡）验签，而是把原文和 USBKey 产生的国密 P7
送到加密平台的 U013 服务验签。所有连接参数来自 config.yml，见 jumpserver/conf.py 中 CPAS_* 配置。
"""
from .client import CPASClient, CPASError, CPASConfigError, CPASTransportError, U013Result
from .p7 import (
    SignerCertificate, P7ParseError, load_signer_certificate,
    normalize_public_key, public_key_matches, summarize as p7_summary, normalize_signed_data, signature_values,
)

__all__ = [
    'CPASClient', 'CPASError', 'CPASConfigError', 'CPASTransportError', 'U013Result',
    'SignerCertificate', 'P7ParseError', 'load_signer_certificate',
    'normalize_public_key', 'public_key_matches', 'p7_summary', 'normalize_signed_data', 'signature_values',
]
