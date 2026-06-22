import base64
import secrets

from rest_framework import exceptions, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from common.api import JMSModelViewSet
from common.permissions import OnlySuperUser
from ..models import UKey, User
from ..serializers import AdminUKeySerializer, UKeySerializer

__all__ = ['UserUKeyViewSet', 'AdminUserUKeyViewSet']


class UserUKeyViewSet(viewsets.ModelViewSet):
    serializer_class = UKeySerializer
    search_fields = (
        "user__name",
        "u_key_serial",
    )
    filterset_fields = ("user",)
    permission_classes = (AllowAny,)

    def get_queryset(self):
        user = self._get_bound_user()
        if not user:
            return UKey.objects.none()
        return UKey.objects.filter(user=user)

    def perform_create(self, serializer):
        user = self._get_bound_user(required=True)
        serializer.save(user=user)

    def perform_update(self, serializer):
        user = self._get_bound_user(required=True)
        serializer.save(user=user)

    def _get_bound_user(self, required=False):
        request_user = self.request.user
        if request_user.is_authenticated:
            return request_user

        user_id = self.request.session.get('user_id') or self.request.data.get('user') or self.request.query_params.get('user')
        if not user_id:
            if required:
                raise exceptions.NotAuthenticated()
            return None
        session_user_id = self.request.session.get('user_id')
        if session_user_id and str(user_id) != str(session_user_id):
            raise exceptions.PermissionDenied()
        user = User.objects.filter(id=user_id).first()
        if not user:
            if required:
                raise exceptions.NotAuthenticated()
            return None
        return user

    @action(detail=False, methods=["get"], url_path="random")
    def get_ukey_random(self, *args, **kwargs):
        random_bytes = secrets.token_bytes(32)
        return Response({"msg": base64.b16encode(random_bytes)}, status=200)


class AdminUserUKeyViewSet(JMSModelViewSet):
    """管理员管理所有用户的 USBKey 绑定信息"""
    serializer_class = AdminUKeySerializer
    permission_classes = (OnlySuperUser,)
    search_fields = ("user__username", "user__name", "u_key_serial")
    filterset_fields = ("user", "u_key_serial")
    ordering_fields = ("u_key_serial", "date_created", "date_updated")
    ordering = ("-date_created",)

    def get_queryset(self):
        return UKey.objects.all().select_related("user")

