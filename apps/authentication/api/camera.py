from django.db import transaction
from django.utils import timezone
from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.models import CommandFaceVerifyRecord
from authentication.serializers import CameraPhotoCallbackSerializer
from authentication.services.face import FaceClient, FaceCompareError
from authentication.services.face_image import decode_base64_image, save_face_verify_image


class IsAccessKeyAuthenticated(BasePermission):
    def has_permission(self, request, view):
        authorization = request.META.get('HTTP_AUTHORIZATION', '')
        is_signature = authorization.lower().startswith('signature ')
        return bool(request.user and request.user.is_authenticated and request.auth and is_signature)


class CameraPhotoCallbackApi(APIView):
    permission_classes = (IsAccessKeyAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = CameraPhotoCallbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        should_compare = False
        with transaction.atomic():
            record = CommandFaceVerifyRecord.objects.select_for_update().filter(
                sign=data['sign']
            ).first()
            if not record:
                return Response({'code': 404, 'msg': 'sign not found', 'data': None}, status=404)

            if record.status != CommandFaceVerifyRecord.StatusChoices.waiting_photo:
                return self.get_response(record, msg='photo already pushed')

            face_content = decode_base64_image(data['faceStr'])
            photo_content = decode_base64_image(data['photoStr'])
            face_info = save_face_verify_image(record, face_content, 'face')
            photo_info = save_face_verify_image(record, photo_content, 'photo')

            record.face_image_path = face_info['path']
            record.face_image_sha256 = face_info['sha256']
            record.face_image_size = face_info['size']
            record.photo_image_path = photo_info['path']
            record.photo_image_sha256 = photo_info['sha256']
            record.photo_image_size = photo_info['size']
            record.status = CommandFaceVerifyRecord.StatusChoices.photo_received
            record.date_callback = timezone.now()
            record.error_message = ''
            record.save(update_fields=[
                'face_image_path', 'face_image_sha256', 'face_image_size',
                'photo_image_path', 'photo_image_sha256', 'photo_image_size',
                'status', 'date_callback', 'error_message', 'date_updated',
            ])
            should_compare = True
        if should_compare:
            self.compare_face(record)
        return self.get_response(record)

    def compare_face(self, record):
        record.status = CommandFaceVerifyRecord.StatusChoices.comparing
        record.save(update_fields=['status', 'date_updated'])
        try:
            result = FaceClient().compare(
                record.face_image_path, record.photo_image_path, seq=str(record.id)
            )
            record.score = result.score
            record.threshold = result.threshold
            record.ai_response = summarize_ai_response(result.response)
            record.status = (
                CommandFaceVerifyRecord.StatusChoices.passed
                if result.passed
                else CommandFaceVerifyRecord.StatusChoices.failed
            )
            record.error_message = '' if result.passed else 'face compare not passed'
        except FaceCompareError as e:
            record.status = CommandFaceVerifyRecord.StatusChoices.error
            record.error_message = e.message
            record.ai_response = summarize_ai_response(e.response)
        record.date_compared = timezone.now()
        if record.status in (
            CommandFaceVerifyRecord.StatusChoices.passed,
            CommandFaceVerifyRecord.StatusChoices.failed,
            CommandFaceVerifyRecord.StatusChoices.error,
        ):
            record.date_finished = record.date_compared
        record.save(update_fields=[
            'score', 'threshold', 'ai_response', 'status', 'error_message',
            'date_compared', 'date_finished', 'date_updated',
        ])

    @staticmethod
    def get_response(record, msg='ok'):
        return Response({
            'code': 200,
            'msg': msg,
            'data': {
                'sign': record.sign,
                'status': record.status,
                'score': record.score,
                'threshold': record.threshold,
                'face_image_size': record.face_image_size,
                'photo_image_size': record.photo_image_size,
            }
        })


def summarize_ai_response(response):
    if not response:
        return {}
    data = response.get('data')
    return {
        'code': response.get('code'),
        'msg': response.get('msg') or response.get('message'),
        'data': data if isinstance(data, dict) else {},
    }
