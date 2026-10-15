from django.db import models
from django.utils.translation import gettext_lazy as _

from common.db import fields
from common.db.models import JMSBaseModel

__all__ = ["UKey"]


class UKey(JMSBaseModel):
    user = models.ForeignKey(
        "users.User",
        on_delete=models.CASCADE,
        related_name="user_usb_key",
        verbose_name=_("User"),
    )
    u_key_serial = models.CharField(
        max_length=128, unique=True, verbose_name=_("USB Key Serial")
    )
    # 保存的是公钥的x+y值，16进制的32位
    u_key_public_key = fields.EncryptTextField(verbose_name=_("USB Key Public Key"))

    class Meta:
        verbose_name = _("User UKey")


# UKey 登录挑战值放在缓存里，按 session key 绑定：random 接口生成时写入，验签时取出并删除（一次性，防重放）。
# 不放 session 的原因：SESSION_SAVE_EVERY_REQUEST 下并发的 API 请求（如 pin-log）会把各自加载的旧 session 整份写回，
# 导致刚写入的挑战值被覆盖丢失。
UKEY_CHALLENGE_CACHE_KEY_PREFIX = "ukey_challenge"


def ukey_challenge_cache_key(session_key):
    return "{}:{}".format(UKEY_CHALLENGE_CACHE_KEY_PREFIX, session_key)
