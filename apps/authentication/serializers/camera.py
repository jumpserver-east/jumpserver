from rest_framework import serializers


class CameraPhotoCallbackSerializer(serializers.Serializer):
    sign = serializers.CharField(required=True, allow_blank=False, max_length=128)
    faceStr = serializers.CharField(required=True, allow_blank=False)
    photoStr = serializers.CharField(required=True, allow_blank=False)
