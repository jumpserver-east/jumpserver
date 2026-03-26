import base64
import time

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from audits.const import ActionChoices
from audits.utils import write_operate_log
from common.sdk.gm import piico
from common.sdk.gm.piico.exception import PiicoError
from common.utils import get_request_ip_or_data
from ..models import UKey, User
from ..serializers import UKeySerializer


def get_auth_user_from_request(request):
    user = getattr(request, "user", None)
    if user and not user.is_anonymous:
        return user

    if request.session.is_empty():
        return None

    user_id = request.session.get("user_id")
    auth_ok = request.session.get("auth_password")
    auth_expired_at = request.session.get("auth_password_expired_at")
    auth_expired = auth_expired_at < time.time() if auth_expired_at else False
    if not user_id or not auth_ok or auth_expired:
        return None
    return User.objects.only("id", "username", "name").filter(pk=user_id).first()


class UserUKeyViewSet(viewsets.ModelViewSet):
    queryset = UKey.objects.all()
    serializer_class = UKeySerializer
    search_fields = (
        "user__name",
        "u_key_serial",
    )
    filterset_fields = ("user",)
    permission_classes = (AllowAny,)

    @action(detail=False, methods=["get"], url_path="random")
    def get_ukey_random(self, *args, **kwargs):
        if not settings.PIICO_DEVICE_ENABLE:
            return Response({"msg": _("Piico device not enabled")}, status=400)

        device = piico.open_piico_device()
        try:
            random_bytes = device.generate_random(32)
            return Response({"msg": base64.b16encode(random_bytes)}, status=200)
        except PiicoError as e:
            return Response({"msg": _("Generate random failed: {}").format(e)}, status=400)
        except Exception:
            return Response({"msg": _("Device not initialized")}, status=400)

    @action(detail=False, methods=["post"], url_path="pin-log")
    def pin_log(self, request, *args, **kwargs):
        status = request.data.get("status")
        if status not in {"success", "failed"}:
            return Response({"msg": _("Invalid status")}, status=400)

        user = get_auth_user_from_request(request)
        ip = get_request_ip_or_data(request) or "0.0.0.0"
        serial = str(request.data.get("serial") or "")[:128]
        reason = str(request.data.get("reason") or "")[:128]
        error_code = str(request.data.get("error_code") or "")[:64]
        after = {
            'Stage': 'PIN verify',
            'Status': status,
        }
        if serial:
            after['Serial'] = serial
        if reason:
            after['Reason'] = reason
        if error_code:
            after['Error code'] = error_code

        write_operate_log(
            user=user,
            action=ActionChoices.login,
            resource_type='UKey',
            resource=serial or 'PIN verify',
            resource_id=getattr(user, 'id', ''),
            remote_addr=ip,
            after=after
        )
        return Response({"msg": "ok"}, status=200)
