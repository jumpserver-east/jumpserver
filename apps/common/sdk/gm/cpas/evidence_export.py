#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 data/logs/ukey_evidence.log 里的 UKey 登录取证记录整理成可交付客户的报告。

独立脚本，只用标准库，不加载 Django，可在 core 容器内直接运行：
  python /opt/jumpserver/apps/common/sdk/gm/cpas/evidence_export.py                      最近一条成功记录
  python /opt/jumpserver/apps/common/sdk/gm/cpas/evidence_export.py --user admin --last 3
  python /opt/jumpserver/apps/common/sdk/gm/cpas/evidence_export.py --serial-no 8a486e3c...  按平台流水号
  python /opt/jumpserver/apps/common/sdk/gm/cpas/evidence_export.py --date 2026-10-15 --result failed
  python /opt/jumpserver/apps/common/sdk/gm/cpas/evidence_export.py --out /tmp/evidence      另存证书/P7/报文文件
  python /opt/jumpserver/apps/common/sdk/gm/cpas/evidence_export.py --json                   原样输出 JSON
日志默认位置为本项目 data/logs/ukey_evidence.log（含按天轮转的历史文件），也可用 --log 指定。
"""
import argparse
import base64
import binascii
import glob
import json
import os
import sys
from pathlib import Path


def default_log_paths():
    root = Path(__file__).resolve().parents[5]        # apps/common/sdk/gm/cpas -> 项目根目录
    base = root / 'data' / 'logs' / 'ukey_evidence.log'
    return [str(base)] + sorted(glob.glob(str(base) + '.*'))


def iter_records(paths):
    for path in paths:
        if not os.path.isfile(path):
            continue
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                start = line.find('{')
                if start < 0:
                    continue
                try:
                    record = json.loads(line[start:])
                except ValueError:
                    continue
                if isinstance(record, dict) and 'challenge' in record:
                    record['_logged'] = line[:start].strip()
                    yield record


def pem(der, label='CERTIFICATE'):
    body = base64.b64encode(der).decode('ascii')
    return '-----BEGIN {0}-----\n{1}\n-----END {0}-----\n'.format(label, '\n'.join(body[i:i + 64] for i in range(0, len(body), 64)))


def render(record):
    cert = record.get('certificate', {})
    sig = record.get('signature', {})
    p7 = record.get('p7', {})
    u013 = record.get('u013', {})
    summary = p7.get('summary', {})
    lines = [
        '==== 堡垒机 UKey 登录身份鉴别证据 ====',
        '时间: {}  用户: {}  来源 IP: {}  UKey 序列号: {}  结果: {}'.format(
            record.get('time'), record.get('user'), record.get('ip'), record.get('ukey_serial'), record.get('result')),
        '身份鉴别方式: 用户名 + 口令 + UKey PIN + UKey 国密 SM2 数字签名（挑战-响应），签名由加密平台（签名验签服务器）U013 验证',
        '',
        '一、挑战值（签名原文），由堡垒机服务端生成、一次性使用',
        '  签名原文: {}'.format(record.get('challenge')),
        '  签名原文 HEX 编码（U013 data 字段内容）: {}'.format(record.get('challenge_hex')),
        '',
        '二、用户数字证书（来自 UKey 产生的 P7）',
        '  subject   = {}'.format(cert.get('subject')),
        '  issuer    = {}'.format(cert.get('issuer')),
        '  serial    = {}'.format(cert.get('serial_hex')),
        '  validity  = {} ~ {}'.format(cert.get('not_before'), cert.get('not_after')),
        '  algorithm = {}'.format(cert.get('algorithm')),
        '  公钥 X||Y = {}'.format(cert.get('public_key_hex')),
        '  SHA-256   = {}'.format(cert.get('sha256')),
        '  证书 Base64(DER) = {}'.format(cert.get('base64')),
        '',
        '三、签名值（SM2，userID={}）'.format(record.get('user_id_sm2')),
        '  r   = {}'.format(sig.get('r_hex')),
        '  s   = {}'.format(sig.get('s_hex')),
        '  DER = {}'.format(sig.get('der_hex')),
        '  P7（GM/T 0010 SignedData，detached={}，证书 {} 张，signatureAlgorithm={}，{} 字节）Base64:'.format(
            summary.get('detached'), summary.get('certificates'), summary.get('signature_algorithm_oid'), summary.get('bytes')),
        '    {}'.format(p7.get('base64')),
        '  送平台前规范化: {}'.format('; '.join(p7.get('normalized') or []) or '无需变更'),
    ]
    if p7.get('sent_base64'):
        lines.append('  送平台的 P7 Base64: {}'.format(p7['sent_base64']))
    lines += ['', '四、加密平台 U013 验签',
              '  接口: {}'.format(u013.get('url')),
              '  流水号: {}'.format(u013.get('serial_no')),
              '  请求报文: {}'.format(json.dumps(u013.get('request'), ensure_ascii=False)),
              '  响应: HTTP {} {}'.format(u013.get('http_status') or '-', u013.get('response_text') or json.dumps(u013.get('response'), ensure_ascii=False) if (u013.get('response_text') or u013.get('response') is not None) else '(无响应)'),
              '  结论: responseCode={} remark={}{}'.format(u013.get('code'), u013.get('remark') or '', ' 耗时 {}ms'.format(u013['elapsed_ms']) if u013.get('elapsed_ms') is not None else '')]
    if u013.get('error'):
        lines.append('  错误: {} {}'.format(u013.get('error'), u013.get('message') or ''))
    lines += ['', '五、结论',
              '  挑战值由堡垒机服务端生成并一次性使用，UKey 用用户证书私钥对挑战值做 SM2 签名，堡垒机将挑战值与签名（含证书）送加密平台验签，'
              + ('平台返回成功，身份鉴别通过。' if record.get('result') == 'success' else '平台未通过验签，登录被拒绝。'), '']
    return '\n'.join(lines)


def export_files(record, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = (record.get('time') or 'unknown').replace(':', '').replace('+', 'p')
    prefix = '{}-{}-'.format(stamp, record.get('user'))
    cert = record.get('certificate', {})
    if cert.get('base64'):
        der = base64.b64decode(cert['base64'])
        (out / (prefix + 'user-cert.cer')).write_bytes(der)
        (out / (prefix + 'user-cert.pem')).write_text(pem(der), encoding='ascii')
    p7 = record.get('p7', {})
    if p7.get('base64'):
        (out / (prefix + 'signature-p7.p7b')).write_bytes(base64.b64decode(p7['base64']))
        (out / (prefix + 'signature-p7.b64')).write_text(p7['base64'] + '\n', encoding='ascii')
    sig = record.get('signature', {})
    if sig.get('r_hex'):
        (out / (prefix + 'signature-raw.hex')).write_text('r={}\ns={}\nder={}\n'.format(sig['r_hex'], sig['s_hex'], sig.get('der_hex')), encoding='ascii')
    (out / (prefix + 'challenge.txt')).write_text('{}\n'.format(record.get('challenge')), encoding='ascii')
    u013 = record.get('u013', {})
    if u013.get('request') is not None:
        (out / (prefix + 'u013-request.json')).write_text(json.dumps(u013['request'], ensure_ascii=False, indent=2), encoding='utf-8')
    if u013.get('response') is not None or u013.get('response_text'):
        (out / (prefix + 'u013-response.json')).write_text(
            u013.get('response_text') or json.dumps(u013.get('response'), ensure_ascii=False, indent=2), encoding='utf-8')
    (out / (prefix + 'report.txt')).write_text(render(record), encoding='utf-8')
    (out / (prefix + 'record.json')).write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--log', nargs='*', help='日志文件路径，默认 data/logs/ukey_evidence.log 及其轮转文件')
    parser.add_argument('--user', help='只看该用户名')
    parser.add_argument('--serial-no', help='只看该平台流水号')
    parser.add_argument('--date', help='只看该日期（前缀匹配，如 2026-10-15）')
    parser.add_argument('--result', choices=('success', 'failed', 'all'), default='success')
    parser.add_argument('--last', type=int, default=1, help='输出最近 N 条，默认 1；0 表示全部')
    parser.add_argument('--json', action='store_true', help='输出原始 JSON 记录')
    parser.add_argument('--out', help='把证书、P7、签名值、报文和报告另存到该目录')
    args = parser.parse_args()
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    paths = args.log or default_log_paths()
    records = []
    for record in iter_records(paths):
        if args.user and record.get('user') != args.user:
            continue
        if args.serial_no and (record.get('u013') or {}).get('serial_no') != args.serial_no:
            continue
        if args.date and not str(record.get('time', '')).startswith(args.date):
            continue
        if args.result != 'all' and record.get('result') != args.result:
            continue
        records.append(record)
    if not records:
        print('没有匹配的记录；日志文件: {}'.format(paths))
        return 1
    if args.last:
        records = records[-args.last:]
    for record in records:
        if args.json:
            print(json.dumps(record, ensure_ascii=False))
        else:
            print(render(record))
        if args.out:
            export_files(record, args.out)
    if args.out:
        print('已导出 {} 条记录的文件到 {}'.format(len(records), args.out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
