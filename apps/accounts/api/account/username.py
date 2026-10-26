import re
from functools import reduce
from operator import or_

from django.db.models import Count, Q
from rest_framework import mixins

from accounts import serializers
from accounts.models import Account
from assets.models import Asset, Node
from common.drf.filters import IDSpmFilterBackend
from jumpserver.rewriting.pagination import MaxLimitOffsetPagination
from orgs.mixins.api import OrgGenericViewSet

__all__ = ['AccountUsernameViewSet']


class AccountUsernamePagination(MaxLimitOffsetPagination):
    def get_count(self, queryset):
        # 默认按 id 计数，会把按用户名分组的结果算成账号数
        return queryset.count()


class AccountUsernameViewSet(mixins.ListModelMixin, OrgGenericViewSet):
    """
    去重后的账号用户名，供改密任务、资产授权批量选择账号
    """
    model = Account
    serializer_class = serializers.AccountUsernameSerializer
    pagination_class = AccountUsernamePagination
    search_fields = ('username',)
    rbac_perms = {
        'list': 'accounts.view_account | accounts.add_changesecretautomation | '
                'accounts.change_changesecretautomation | perms.add_assetpermission | '
                'perms.change_assetpermission',
    }
    ordering_mapper = {'name': 'username', 'username': 'username', 'asset_amount': 'asset_amount'}

    @staticmethod
    def get_spm_ids(spm):
        return IDSpmFilterBackend.get_resource_ids(spm) or []

    def filter_scope(self, queryset):
        # 资产、节点通过 spm 传入，避免选择大量资产时 URL 过长
        asset_spm = self.request.query_params.get('asset_spm')
        node_spm = self.request.query_params.get('node_spm')
        if not asset_spm and not node_spm:
            return queryset

        conditions = []
        asset_ids = self.get_spm_ids(asset_spm) if asset_spm else []
        if asset_ids:
            conditions.append(Q(asset_id__in=asset_ids))
        node_ids = self.get_spm_ids(node_spm) if node_spm else []
        nodes = Node.objects.filter(id__in=node_ids)
        if nodes:
            node_assets = Node.get_nodes_all_assets(*nodes).values('id')
            conditions.append(Q(asset_id__in=node_assets))
        if not conditions:
            return queryset.none()

        asset_q = reduce(or_, conditions)
        through = Asset.directory_services.through
        ds_ids = through.objects.filter(asset_q).values('directoryservice_id')
        return queryset.filter(asset_q | Q(asset_id__in=ds_ids))

    @staticmethod
    def split_terms(value):
        return [term.strip() for term in re.split(r'[,|]', value or '') if term.strip()]

    def filter_keyword(self, queryset):
        # 兼容表格搜索框：search 中逗号、竖线分隔的词任一匹配，search__icontains_all 需全部匹配
        params = self.request.query_params
        any_terms = []
        for key in ('search', 'q', 'username', 'search__icontains_any'):
            for value in params.getlist(key):
                any_terms.extend(self.split_terms(value))
        if any_terms:
            queryset = queryset.filter(reduce(or_, (Q(username__icontains=t) for t in any_terms)))
        for value in params.getlist('search__icontains_all'):
            for term in self.split_terms(value):
                queryset = queryset.filter(username__icontains=term)
        return queryset

    def filter_queryset(self, queryset):
        params = self.request.query_params
        queryset = self.filter_scope(queryset)

        secret_type = params.get('secret_type')
        if secret_type:
            queryset = queryset.filter(secret_type=secret_type)
        queryset = self.filter_keyword(queryset)
        spm = params.get('spm')
        if spm:
            queryset = queryset.filter(username__in=self.get_spm_ids(spm))
        exclude_spm = params.get('exclude_spm')
        if exclude_spm:
            queryset = queryset.exclude(username__in=self.get_spm_ids(exclude_spm))

        queryset = queryset.order_by().values('username') \
            .annotate(asset_amount=Count('asset_id', distinct=True))

        order = params.get('order', '')
        desc = order.startswith('-')
        field = self.ordering_mapper.get(order.lstrip('-'), 'username')
        queryset = queryset.order_by(f'-{field}' if desc else field, 'username')
        return self.limit_queryset_if_no_page(queryset)

    def paginate_queryset(self, queryset):
        # 结果是按用户名聚合的字典，不需要像模型列表那样按 id 重新查询
        if self.paginator is None:
            return None
        return self.paginator.paginate_queryset(queryset, self.request, view=self)
