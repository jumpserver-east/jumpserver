from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from common.serializers.fields import EncryptedField
from ..models import UKey


class UKeySerializer(serializers.ModelSerializer):
    u_key_public_key = EncryptedField(write_only=True, label=_("USB Key Public Key"))

    class Meta:
        model = UKey
        read_only_fields = ['date_created', 'date_updated']
        fields = ['id', 'user', 'u_key_serial', 'u_key_public_key'] + read_only_fields


class AdminUKeySerializer(serializers.ModelSerializer):
    u_key_public_key = EncryptedField(write_only=True, label=_("USB Key Public Key"))
    username = serializers.CharField(source='user.username', read_only=True, label=_("Username"))
    user_display = serializers.CharField(source='user.name', read_only=True, label=_("Name"))

    class Meta:
        model = UKey
        read_only_fields = ['username', 'user_display', 'date_created', 'date_updated']
        fields = ['id', 'user', 'u_key_serial', 'u_key_public_key'] + read_only_fields
        extra_kwargs = {
            'user': {'label': _("User")},
            'u_key_serial': {'label': _("USB Key Serial")},
        }
