from django.conf import settings

from ..base.device import Device


class PiicoDevice(Device):
    name = "piico"

    def __init__(self, driver_path=None):
        driver_path = driver_path or settings.PIICO_DRIVER_PATH or "./lib/libpiico_ccmu.so"
        self.open(driver_path)

    # 默认去lib路径检索
    def open(self, driver_path="libpiico_ccmu.so"):
        super().open(driver_path)

    def new_key_manager(self):
        from .key_management import PiicoKeyManager

        return PiicoKeyManager(self)
