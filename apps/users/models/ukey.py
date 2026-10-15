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


# UKey 登录挑战值在 session 中的键：random 接口生成时写入，验签时取出并删除（一次性，防重放）
UKEY_CHALLENGE_SESSION_KEY = "ukey_challenge"
UKEY_CHALLENGE_EXPIRED_AT_SESSION_KEY = "ukey_challenge_expired_at"
