from django.db import transaction
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response

from authentication.models import CommandFaceVerifyRecord
from authentication.services.camera import trigger_command_face_verify, wait_command_face_verify
from common.permissions import IsValidUser
from common.utils import get_logger
from orgs.mixins.api import OrgBulkModelViewSet
from .common import ACLUserAssetFilterMixin
from .. import models, serializers

__all__ = ['CommandFilterACLViewSet', 'CommandGroupViewSet']

logger = get_logger(__file__)


class CommandGroupViewSet(OrgBulkModelViewSet):
    model = models.CommandGroup
    filterset_fields = ('name', 'command_filters')
    search_fields = ('name',)
    serializer_class = serializers.CommandGroupSerializer


class CommandACLFilter(ACLUserAssetFilterMixin):
    class Meta:
        model = models.CommandFilterACL
        fields = ['name', ]


class CommandFilterACLViewSet(OrgBulkModelViewSet):
    model = models.CommandFilterACL
    filterset_class = CommandACLFilter
    search_fields = ['name']
    serializer_class = serializers.CommandFilterACLSerializer
    rbac_perms = {
        'command_review': '*',
        'command_face_review': '*',
    }

    @transaction.non_atomic_requests
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    @action(['POST'], detail=False, url_path='command-review', permission_classes=[IsValidUser])
    def command_review(self, request, *args, **kwargs):
        serializer = serializers.CommandReviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validate_command_review_session_user(request.user, serializer.session)
        data = {
            'run_command': serializer.validated_data['run_command'],
            'session': serializer.session,
            'cmd_filter_acl': serializer.cmd_filter_acl,
            'org_id': serializer.org.id
        }
        ticket = serializer.cmd_filter_acl.create_command_review_ticket(**data)
        info = ticket.get_extra_info_of_review(user=request.user)
        return Response(data=info)

    @action(['POST'], detail=False, url_path='command-face-review', permission_classes=[IsValidUser])
    def command_face_review(self, request, *args, **kwargs):
        serializer = serializers.CommandReviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validate_command_review_session_user(request.user, serializer.session)
        data = {
            'run_command': serializer.validated_data['run_command'],
            'session': serializer.session,
            'cmd_filter_acl': serializer.cmd_filter_acl,
            'org_id': serializer.org.id
        }
        face_record = None
        try:
            face_record = trigger_command_face_verify(**data)
        except Exception as e:
            logger.warning('Trigger command face verify failed: %s', e)
        if not face_record:
            raise ValidationError({
                'code': 'face_verify_camera_failed',
                'detail': 'Trigger command face verify failed'
            })
        face_record = wait_command_face_verify(face_record)
        if face_record.status != CommandFaceVerifyRecord.StatusChoices.passed:
            raise ValidationError({
                'code': get_face_verify_error_code(face_record.status),
                'detail': face_record.error_message or face_record.get_status_display()
            })
        ticket = serializer.cmd_filter_acl.create_command_review_ticket(**data)
        face_record.ticket_id = ticket.id
        face_record.save(update_fields=['ticket_id', 'date_updated'])
        info = ticket.get_extra_info_of_review(user=request.user)
        return Response(data=info)


def validate_command_review_session_user(user, session):
    if user.is_superuser or user.is_service_account:
        return
    if str(user.id) == str(session.user_id):
        return
    raise PermissionDenied('Session does not belong to current user')


def get_face_verify_error_code(status):
    mapper = {
        CommandFaceVerifyRecord.StatusChoices.token_failed: 'face_verify_token_failed',
        CommandFaceVerifyRecord.StatusChoices.camera_call_failed: 'face_verify_camera_failed',
        CommandFaceVerifyRecord.StatusChoices.timeout: 'face_verify_photo_timeout',
        CommandFaceVerifyRecord.StatusChoices.failed: 'face_verify_rejected',
        CommandFaceVerifyRecord.StatusChoices.error: 'face_verify_compare_failed',
    }
    return mapper.get(status, 'face_verify_compare_failed')
