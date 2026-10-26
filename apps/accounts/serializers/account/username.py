from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

__all__ = ['AccountUsernameSerializer']


class AccountUsernameSerializer(serializers.Serializer):
    id = serializers.CharField(source='username', read_only=True)
    name = serializers.CharField(source='username', read_only=True, label=_('Username'))
    asset_amount = serializers.IntegerField(read_only=True, label=_('Assets amount'))
