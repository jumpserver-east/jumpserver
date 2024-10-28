# -*- coding: utf-8 -*-
#
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts import serializers
from accounts.const import AutomationTypes
from accounts.filters import GatheredAccountFilterSet
from accounts.models import GatherAccountsAutomation, AutomationExecution
from accounts.models import GatheredAccount
from assets.models import Asset
from orgs.mixins.api import OrgBulkModelViewSet
from .base import AutomationExecutionViewSet

__all__ = [
    'GatherAccountsAutomationViewSet', 'GatherAccountsExecutionViewSet',
    'GatheredAccountViewSet'
]


class GatherAccountsAutomationViewSet(OrgBulkModelViewSet):
    model = GatherAccountsAutomation
    filterset_fields = ('name',)
    search_fields = filterset_fields
    serializer_class = serializers.GatherAccountAutomationSerializer


class GatherAccountsExecutionViewSet(AutomationExecutionViewSet):
    rbac_perms = (
        ("list", "accounts.view_gatheraccountsexecution"),
        ("retrieve", "accounts.view_gatheraccountsexecution"),
        ("create", "accounts.add_gatheraccountsexecution"),
    )

    tp = AutomationTypes.gather_accounts

    def get_queryset(self):
        queryset = super().get_queryset()
        queryset = queryset.filter(automation__type=self.tp)
        return queryset


class GatheredAccountViewSet(OrgBulkModelViewSet):
    model = GatheredAccount
    search_fields = ('username',)
    filterset_class = GatheredAccountFilterSet
    serializer_classes = {
        'default': serializers.GatheredAccountSerializer,
    }
    rbac_perms = {
        'sync_accounts': 'assets.add_gatheredaccount',
        'discover': 'assets.add_gatheredaccount',
    }

    @action(methods=['get'], detail=False, url_path='discover')
    def discover(self, request, *args, **kwargs):
        asset_id = request.query_params.get('asset_id')
        if not asset_id:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={'asset_id': 'This field is required.'})
        asset = get_object_or_404(Asset, pk=asset_id)
        execution = AutomationExecution()
        execution.snapshot = {
            'assets': [asset_id],
            'nodes': [],
            'type': 'gather_accounts',
            'is_sync_account': True,
            'name': 'Adhoc gather accounts: {}'.format(asset_id),
        }
        execution.save()
        execution.start()
        accounts = self.model.objects.filter(asset=asset)
        serializer = self.get_serializer(accounts, many=True)
        return Response(status=status.HTTP_200_OK, data=serializer.data)

    @action(methods=['post'], detail=False, url_path='sync-accounts')
    def sync_accounts(self, request, *args, **kwargs):
        gathered_account_ids = request.data.get('gathered_account_ids')
        gathered_accounts = self.model.objects.filter(id__in=gathered_account_ids)
        self.model.sync_accounts(gathered_accounts)
        return Response(status=status.HTTP_201_CREATED)
