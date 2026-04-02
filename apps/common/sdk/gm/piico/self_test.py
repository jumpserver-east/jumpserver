import time

from .const import (
    ECC_POINT_UNCOMPRESSED,
    SGD_SM2,
    SGD_SM2_3,
    SGD_SM3,
    SGD_SM4_CBC,
    SGD_SM4_ECB,
)

SM3_TEST_INPUT = b"abcd" * 16
SM3_TEST_EXPECTED = bytes.fromhex("DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732")

SM4_ECB_KEY = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
SM4_ECB_PLAIN_TEXT = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
SM4_ECB_CIPHER_EXPECTED = bytes.fromhex("681EDF34D206965E86B3E94F536E4246")

SM4_CBC_KEY = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
SM4_CBC_IV = bytes.fromhex("EBEEC56858E604D8327B9B3C10C90CA7")
SM4_CBC_PLAIN_TEXT = bytes.fromhex(
    "0123456789ABCDEFFEDCBA9876543210"
    "29BEE1D65249F1E9B3DB873E240D0647"
)
SM4_CBC_CIPHER_EXPECTED = bytes.fromhex(
    "3F1E73C3DFD5A132882FE69D996CDE93"
    "5499095DDE68995B4D70F2309F2EF1B7"
)


def _elapsed_ms(started):
    return int((time.monotonic() - started) * 1000)


def _close_quietly(resource):
    if resource is None:
        return
    try:
        resource.close()
    except Exception:
        pass


def _format_error(exc):
    return f"{type(exc).__name__}: {exc}"


def _normalize_sm2_public_key(public_key):
    if len(public_key) == 65 and public_key[:1] == bytes([ECC_POINT_UNCOMPRESSED]):
        return public_key[1:]
    if len(public_key) == 64:
        return public_key
    raise ValueError(f"Unsupported SM2 public key length: {len(public_key)}")


def _run_random_test(device, length=64):
    session = device.new_session()
    try:
        random_bytes = session.generate_random(length)
    finally:
        _close_quietly(session)

    if len(random_bytes) != length:
        raise ValueError(f"Random length mismatch: expected {length}, got {len(random_bytes)}")

    return {
        "length": len(random_bytes),
        "sample_hex": random_bytes[:16].hex().upper(),
    }


def _run_sm3_hash_test(device):
    session = device.new_session()
    try:
        session.hash_init(SGD_SM3)
        session.hash_update(SM3_TEST_INPUT)
        digest = session.hash_final()
    finally:
        _close_quietly(session)

    if digest != SM3_TEST_EXPECTED:
        raise ValueError(
            f"SM3 digest mismatch: expected {SM3_TEST_EXPECTED.hex().upper()}, got {digest.hex().upper()}"
        )

    return {
        "input_len": len(SM3_TEST_INPUT),
        "digest_hex": digest.hex().upper(),
    }


def _run_sm2_encrypt_decrypt_test(device):
    session = device.new_session()
    try:
        key_pair = session.generate_ecc_key_pair(SGD_SM2)
        plain_text = session.generate_random(32)
        public_key = _normalize_sm2_public_key(key_pair.public_key)
        cipher_text = session.ecc_encrypt(public_key, plain_text, SGD_SM2_3)
        decrypted = session.ecc_decrypt(key_pair.private_key, cipher_text, SGD_SM2_3)
    finally:
        _close_quietly(session)

    if decrypted != plain_text:
        raise ValueError("SM2 decrypt result does not match plaintext")

    return {
        "plain_len": len(plain_text),
        "cipher_len": len(cipher_text),
        "public_key_prefix": key_pair.public_key[:1].hex().upper(),
    }


def _run_sm4_ecb_test(device):
    session = device.new_session()
    try:
        encrypted = bytes(session.encrypt(SM4_ECB_PLAIN_TEXT, SM4_ECB_KEY, SGD_SM4_ECB))
        decrypted = bytes(session.decrypt(SM4_ECB_CIPHER_EXPECTED, SM4_ECB_KEY, SGD_SM4_ECB))
    finally:
        _close_quietly(session)

    if encrypted != SM4_ECB_CIPHER_EXPECTED:
        raise ValueError(
            f"SM4 ECB encrypt mismatch: expected {SM4_ECB_CIPHER_EXPECTED.hex().upper()}, "
            f"got {encrypted.hex().upper()}"
        )
    if decrypted != SM4_ECB_PLAIN_TEXT:
        raise ValueError(
            f"SM4 ECB decrypt mismatch: expected {SM4_ECB_PLAIN_TEXT.hex().upper()}, "
            f"got {decrypted.hex().upper()}"
        )

    return {
        "cipher_hex": encrypted.hex().upper(),
        "plain_len": len(decrypted),
    }


def _run_sm4_cbc_test(device):
    session = device.new_session()
    try:
        encrypted = bytes(session.encrypt(SM4_CBC_PLAIN_TEXT, SM4_CBC_KEY, SGD_SM4_CBC, SM4_CBC_IV))
        decrypted = bytes(session.decrypt(SM4_CBC_CIPHER_EXPECTED, SM4_CBC_KEY, SGD_SM4_CBC, SM4_CBC_IV))
    finally:
        _close_quietly(session)

    if encrypted != SM4_CBC_CIPHER_EXPECTED:
        raise ValueError(
            f"SM4 CBC encrypt mismatch: expected {SM4_CBC_CIPHER_EXPECTED.hex().upper()}, "
            f"got {encrypted.hex().upper()}"
        )
    if decrypted != SM4_CBC_PLAIN_TEXT:
        raise ValueError(
            f"SM4 CBC decrypt mismatch: expected {SM4_CBC_PLAIN_TEXT.hex().upper()}, "
            f"got {decrypted.hex().upper()}"
        )

    return {
        "cipher_hex": encrypted.hex().upper(),
        "plain_len": len(decrypted),
    }


PIICO_SELF_TEST_CASES = {
    "random": _run_random_test,
    "sm3": _run_sm3_hash_test,
    "sm2_encrypt_decrypt": _run_sm2_encrypt_decrypt_test,
    "sm4_ecb": _run_sm4_ecb_test,
    "sm4_cbc": _run_sm4_cbc_test,
}

PIICO_SELF_TEST_LABELS = {
    "random": "随机数功能",
    "sm3": "SM3 算法功能",
    "sm2_encrypt_decrypt": "SM2 算法功能",
    "sm4_ecb": "SM4 ECB 算法功能",
    "sm4_cbc": "SM4 CBC 算法功能",
}

DEFAULT_PIICO_SELF_TESTS = tuple(PIICO_SELF_TEST_CASES.keys())


def _open_device(driver_path=None):
    from django.conf import settings

    from . import DEFAULT_DRIVER_PATH, open_piico_device

    if driver_path is None:
        driver_path = settings.PIICO_DRIVER_PATH or DEFAULT_DRIVER_PATH
    device = open_piico_device(driver_path=driver_path)
    return device, driver_path


def run_piico_self_test(driver_path=None, test_names=None):
    from django.conf import settings

    from . import DEFAULT_DRIVER_PATH

    selected_test_names = tuple(test_names or DEFAULT_PIICO_SELF_TESTS)
    invalid_test_names = [name for name in selected_test_names if name not in PIICO_SELF_TEST_CASES]
    if invalid_test_names:
        raise ValueError(f"Unknown Piico self tests: {', '.join(sorted(invalid_test_names))}")

    started = time.monotonic()
    result = {
        "ok": False,
        "driver_path": driver_path or settings.PIICO_DRIVER_PATH or DEFAULT_DRIVER_PATH,
        "tests": [],
    }
    device = None

    try:
        device, resolved_driver_path = _open_device(driver_path=driver_path)
        result["driver_path"] = resolved_driver_path
        for name in selected_test_names:
            case_started = time.monotonic()
            try:
                details = PIICO_SELF_TEST_CASES[name](device)
                result["tests"].append({
                    "name": name,
                    "ok": True,
                    "elapsed_ms": _elapsed_ms(case_started),
                    "details": details,
                })
            except Exception as exc:
                result["tests"].append({
                    "name": name,
                    "ok": False,
                    "elapsed_ms": _elapsed_ms(case_started),
                    "error": _format_error(exc),
                })
        result["ok"] = all(item["ok"] for item in result["tests"])
    except Exception as exc:
        result["error"] = _format_error(exc)
    finally:
        if device is not None:
            try:
                device.close()
            except Exception as exc:
                result["close_error"] = _format_error(exc)
        result["elapsed_ms"] = _elapsed_ms(started)
        if result.get("error") or result.get("close_error"):
            result["ok"] = False

    return result


def summarize_piico_self_test(result):
    if result.get("error"):
        return f"Piico self-test failed: {result['error']}"
    if result.get("skipped"):
        return f"Piico self-test skipped: {result.get('reason', 'skipped')}"

    failed_items = [
        f"{item['name']}={item.get('error', 'failed')}"
        for item in result.get("tests", [])
        if not item.get("ok")
    ]
    status = "ok" if result.get("ok") else "failed"
    summary = f"Piico self-test {status} ({result.get('elapsed_ms', 0)}ms)"
    if failed_items:
        summary = f"{summary}: {'; '.join(failed_items)}"
    if result.get("close_error"):
        summary = f"{summary}; close={result['close_error']}"
    return summary


def _stringify_details(details):
    if not details:
        return ""
    return ", ".join(
        f"{key}={details[key]}"
        for key in sorted(details)
    )


def _get_test_label(name):
    return PIICO_SELF_TEST_LABELS.get(name, name)


def _format_test_result_line(item):
    label = _get_test_label(item.get("name"))
    status = "正常" if item.get("ok") else "异常"
    line = f"{label}{status}"
    elapsed_ms = item.get("elapsed_ms", 0)
    if elapsed_ms >= 0:
        line = f"{line} ({elapsed_ms}ms)"
    if item.get("ok"):
        details = _stringify_details(item.get("details", {}))
        if details:
            line = f"{line} {details}"
    elif item.get("error"):
        line = f"{line}: {item['error']}"
    return line


def format_piico_self_test_report_lines(result):
    if result.get("skipped"):
        overall_line = "加密模块自检已跳过"
    else:
        overall_line = "加密模块自检结果: 正常" if result.get("ok") else "加密模块自检结果: 异常"

    lines = [overall_line, summarize_piico_self_test(result)]

    driver_path = result.get("driver_path")
    if driver_path:
        lines.append(f"驱动路径: {driver_path}")

    if result.get("skipped"):
        lines.append(f"跳过原因: {result.get('reason', 'skipped')}")

    if result.get("error"):
        lines.append(f"错误信息: {result['error']}")

    for item in result.get("tests", []):
        lines.append(_format_test_result_line(item))

    if result.get("close_error"):
        lines.append(f"关闭设备异常: {result['close_error']}")

    return lines
