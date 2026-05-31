import re

from django.db import transaction
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response

from authentication.models import CommandFaceVerifyRecord
from authentication.services.camera import trigger_command_face_verify, wait_command_face_verify
from common.permissions import IsValidUser
from common.utils import get_logger
from orgs.mixins.api import OrgBulkModelViewSet
from terminal.const import TaskNameType
from terminal.models import Task
from .common import ACLUserAssetFilterMixin
from .. import models, serializers

__all__ = ['CommandFilterACLViewSet', 'CommandGroupViewSet']

logger = get_logger(__file__)
FACE_VERIFY_FAILED_LIMIT = 3
FACE_VERIFY_TERMINATED_BY = 'face_verify'
MAX_FACE_VERIFY_DETAIL_LENGTH = 80
SENSITIVE_DETAIL_PATTERN = re.compile(
    r'(?i)(authorization|accessToken|access_token|token|signData|idNumber|faceStr|photoStr)'
)


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
            failed_count = get_continuous_face_compare_failed_count(face_record)
            terminate_session = failed_count >= FACE_VERIFY_FAILED_LIMIT
            if terminate_session:
                create_face_verify_kill_session_task(serializer.session)
            raise ValidationError({
                'code': get_face_verify_error_code(face_record.status),
                'detail': get_face_verify_error_detail(face_record, failed_count, terminate_session)
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


def get_face_verify_error_detail(record, failed_count=0, terminate_session=False):
    detail = normalize_face_verify_error_detail(record.error_message)
    if is_id_number_error(detail):
        stage_message = '人脸核验失败：获取用户身份证号失败'
    elif is_camera_face_missing_error(detail):
        stage_message = '人脸核验失败：拍照系统未返回用户人脸信息'
    elif is_callback_image_error(detail):
        stage_message = '人脸核验失败：拍照系统回调图片异常'
    else:
        stage_message = get_face_verify_stage_message(record.status)
    if record.status == CommandFaceVerifyRecord.StatusChoices.failed:
        stage_message = '{}，当前连续失败 {} 次，连续失败 {} 次将中断会话'.format(
            stage_message, failed_count, FACE_VERIFY_FAILED_LIMIT
        )
    if terminate_session:
        stage_message = '{}，当前会话将被中断'.format(stage_message)
    if detail:
        return '{}（{}）'.format(stage_message, detail)
    return stage_message


def normalize_face_verify_error_detail(detail):
    detail = str(detail or '').strip()
    if not detail or SENSITIVE_DETAIL_PATTERN.search(detail):
        return ''
    if is_low_level_exception_detail(detail):
        return ''
    detail = detail.replace('\r', ' ').replace('\n', ' ')
    detail = re.sub(r'\s+', ' ', detail)
    if len(detail) > MAX_FACE_VERIFY_DETAIL_LENGTH:
        detail = '{}...'.format(detail[:MAX_FACE_VERIFY_DETAIL_LENGTH])
    return detail


def is_low_level_exception_detail(detail):
    detail_lower = detail.lower()
    markers = (
        'httpconnectionpool',
        'httpsconnectionpool',
        'max retries exceeded',
        'connection refused',
        'connect timeout',
        'read timed out',
        'newconnectionerror',
        'jsondecodeerror',
        'expecting value',
        'badstatusline',
        'traceback',
    )
    return any(marker in detail_lower for marker in markers)


def get_face_verify_stage_message(status):
    mapper = {
        CommandFaceVerifyRecord.StatusChoices.token_failed: '人脸核验失败：获取拍照系统 token 失败',
        CommandFaceVerifyRecord.StatusChoices.camera_call_failed: '人脸核验失败：调用拍照系统失败',
        CommandFaceVerifyRecord.StatusChoices.timeout: '人脸核验失败：等待拍照系统回调超时',
        CommandFaceVerifyRecord.StatusChoices.failed: '人脸核验失败：人脸比对不通过',
        CommandFaceVerifyRecord.StatusChoices.error: '人脸核验失败：人脸比对服务配置缺失或调用异常',
    }
    return mapper.get(status, '人脸核验失败：未知异常')


def is_id_number_error(detail):
    detail = detail.lower()
    return 'id number' in detail or '身份证' in detail


def is_callback_image_error(detail):
    detail = detail.lower()
    markers = (
        'base64 image',
        'image data',
        'invalid image',
        'image is too large',
        '图片',
    )
    return any(marker in detail for marker in markers)


def is_camera_face_missing_error(detail):
    detail = detail.lower()
    markers = (
        'camera face image is empty',
        'face image is empty',
        'facestr is empty',
        '人脸信息',
    )
    return any(marker in detail for marker in markers)


def get_continuous_face_compare_failed_count(record):
    if record.status != CommandFaceVerifyRecord.StatusChoices.failed:
        return 0

    records = CommandFaceVerifyRecord.objects.filter(
        session_id=record.session_id,
    ).order_by('-date_created').only('status')

    count = 0
    for item in records:
        if item.status == CommandFaceVerifyRecord.StatusChoices.failed:
            count += 1
            continue
        break
    return count


def create_face_verify_kill_session_task(session):
    if session.is_finished:
        return
    exists = Task.objects.filter(
        name=TaskNameType.kill_session,
        args=session.id,
        is_finished=False,
    ).exists()
    if exists:
        return
    Task.objects.create(
        name=TaskNameType.kill_session,
        args=session.id,
        terminal=session.terminal,
        kwargs={
            'terminated_by': FACE_VERIFY_TERMINATED_BY,
            'created_by': FACE_VERIFY_TERMINATED_BY,
        }
    )
