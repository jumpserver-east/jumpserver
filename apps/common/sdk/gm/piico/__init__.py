from django.conf import settings

from .device import PiicoDevice
from .key_management import KeyAlgorithm, KeyCategory, KeyMetadata, KeyState, PiicoKeyManager
from .self_test import (
    DEFAULT_PIICO_SELF_TESTS,
    format_piico_self_test_report_lines,
    run_piico_self_test,
    summarize_piico_self_test,
)

DEFAULT_DRIVER_PATH = "./lib/libpiico_ccmu.so"
Device = PiicoDevice

__all__ = [
    "DEFAULT_DRIVER_PATH",
    "DEFAULT_PIICO_SELF_TESTS",
    "Device",
    "PiicoDevice",
    "format_piico_self_test_report_lines",
    "KeyAlgorithm",
    "KeyCategory",
    "KeyMetadata",
    "KeyState",
    "open_piico_device",
    "PiicoKeyManager",
    "run_piico_self_test",
    "summarize_piico_self_test",
]


def open_piico_device(driver_path=None) -> PiicoDevice:
    if driver_path is None:
        driver_path = settings.PIICO_DRIVER_PATH or DEFAULT_DRIVER_PATH
    return PiicoDevice(driver_path=driver_path)
