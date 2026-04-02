from django.conf import settings

from .device import Device
from .self_test import (
    DEFAULT_PIICO_SELF_TESTS,
    format_piico_self_test_report_lines,
    run_piico_self_test,
    summarize_piico_self_test,
)

DEFAULT_DRIVER_PATH = "./lib/libpiico_ccmu.so"

__all__ = [
    "DEFAULT_DRIVER_PATH",
    "DEFAULT_PIICO_SELF_TESTS",
    "Device",
    "format_piico_self_test_report_lines",
    "open_piico_device",
    "run_piico_self_test",
    "summarize_piico_self_test",
]


def open_piico_device(driver_path=None) -> Device:
    if driver_path is None:
        driver_path = settings.PIICO_DRIVER_PATH or DEFAULT_DRIVER_PATH
    d = Device()
    d.open(driver_path)
    return d
