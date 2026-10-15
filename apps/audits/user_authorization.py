import csv
from io import StringIO
from tempfile import SpooledTemporaryFile

from django.db.models import F, Prefetch, Q
from django.http import FileResponse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer

from accounts.const import AliasAccount
from assets.models import Asset, Node
from common.drf.const import CSV_FILE_ESCAPE_CHARS
from common.drf.renders.mixins import LogMixin
from orgs.mixins.api import OrgReadonlyModelViewSet
from orgs.utils import tmp_to_org
from perms.models import AssetPermission
from perms.utils.asset_perm import PermAssetDetailUtil
from perms.utils.user_perm import AssetPermissionPermAssetUtil
from tickets.const import StepState
from tickets.models import TicketAssignee
from users.models import User
from .models import UserAuthorization


def valid_permissions():
    now = timezone.now()
    return AssetPermission.objects.filter(
        is_active=True, date_start__lt=now, date_expired__gt=now
    )


def permissions_for_user(user):
    return valid_permissions().filter(
        Q(users=user) | Q(user_groups__users=user, user_groups__org_id=F('org_id'))
    ).distinct()


def permission_assets(permission):
    # Evaluate node expansion in the rule's organization, including in the global view.
    with tmp_to_org(permission.org_id):
        assets = AssetPermissionPermAssetUtil([permission.id]).get_all_assets()
    return assets.filter(org_id=permission.org_id).order_by('name', 'id')


def permission_grantor(permission):
    if not permission.from_ticket:
        return permission.created_by or str(_('Unknown'))
    approvals = TicketAssignee.objects.filter(
        step__ticket_id=permission.id,
        step__ticket__org_id=permission.org_id,
        step__state=StepState.approved,
        state=StepState.approved,
    ).select_related('assignee').order_by('step__level', 'assignee__username')
    names = dict.fromkeys(str(approval.assignee) for approval in approvals)
    return '; '.join(names) or str(_('Unknown'))


def asset_groups(asset):
    return '; '.join(sorted({
        node.full_value for node in asset.nodes.all()
        if node.org_id == asset.org_id and node.full_value
    }))


def permission_accounts(permission, asset):
    # Reuse connection-time rules for @ALL, exclusions and action filtering.
    # Resolve usernames only; account secrets are not needed for an audit export.
    with tmp_to_org(permission.org_id):
        aliases, _ = PermAssetDetailUtil.parse_alias_action_date_expire([permission], asset)
        usernames = set(asset.all_valid_accounts.filter(
            org_id=permission.org_id
        ).values_list('username', flat=True))
    accounts = set(aliases) & usernames
    if AliasAccount.USER in aliases:
        accounts.add(AliasAccount.USER)
    for alias in (AliasAccount.INPUT, AliasAccount.ANON):
        if alias in aliases:
            accounts.add(f'{alias.value} ({alias.label})')
    return accounts


class UserAuthorizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAuthorization
        fields = ['id', 'username', 'name']
        read_only_fields = fields


class AuthorizationRuleSerializer(serializers.ModelSerializer):
    grantor = serializers.SerializerMethodField(label=_('Granted by'))

    class Meta:
        model = AssetPermission
        fields = ['id', 'name', 'grantor', 'date_start', 'date_expired']
        read_only_fields = fields
        extra_kwargs = {
            'name': {'label': _('Authorization rule name')},
            'date_start': {'label': _('Authorization start time')},
            'date_expired': {'label': _('Authorization expiration time')},
        }

    def get_grantor(self, obj):
        return permission_grantor(obj)


class AuthorizationAssetSerializer(serializers.ModelSerializer):
    asset_groups = serializers.SerializerMethodField(label=_('Asset groups'))

    class Meta:
        model = Asset
        fields = ['id', 'name', 'address', 'asset_groups']
        read_only_fields = fields
        extra_kwargs = {
            'name': {'label': _('Authorized asset')},
            'address': {'label': _('Asset IP')},
        }

    def get_asset_groups(self, obj):
        return asset_groups(obj)


EXPORT_HEADERS = (
    _('Username'), _('Granted by'), _('Authorization rule name'),
    _('Authorization start time'), _('Authorization expiration time'),
    _('Authorized asset'), _('Asset IP'), _('Asset groups'),
    _('Accounts available to user'),
)
EXCEL_SHEET_ROWS = 1048576


def authorization_rows(users):
    permissions = valid_permissions().filter(
        Q(users__in=users) |
        Q(user_groups__users__in=users, user_groups__org_id=F('org_id'))
    ).distinct().order_by('name', 'id')
    for permission in permissions.iterator(chunk_size=100):
        # The user table is global; membership must also match each rule's organization.
        members = User.get_org_users(org=permission.org)
        group_ids = permission.user_groups.filter(org_id=permission.org_id).values('id')
        granted_users = list(users.filter(
            Q(id__in=permission.users.values('id')) | Q(groups__in=group_ids),
            id__in=members.values('id'),
        ).distinct().order_by('username', 'id').values_list('username', flat=True))
        if not granted_users:
            continue
        grantor = permission_grantor(permission)
        dates = [timezone.localtime(value).strftime('%Y-%m-%d %H:%M:%S %z')
                 for value in (permission.date_start, permission.date_expired)]
        nodes = Node.objects.filter(org_id=permission.org_id).only('id', 'org_id', 'full_value')
        assets = permission_assets(permission).prefetch_related(Prefetch('nodes', queryset=nodes))
        for asset in assets.iterator(chunk_size=500):
            groups = asset_groups(asset)
            accounts = permission_accounts(permission, asset)
            for username in granted_users:
                account_names = '; '.join(sorted({
                    username if account == AliasAccount.USER else account for account in accounts
                }))
                yield [username, grantor, permission.name, *dates, asset.name, asset.address, groups,
                       account_names]


def export_authorizations(rows, file_format):
    """Write every expanded row without the generic renderer's 10,000-row truncation."""
    output = SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode='w+b')
    count = 0
    try:
        if file_format == 'csv':
            output.write(b'\xef\xbb\xbf')
            buffer = StringIO()
            writer = csv.writer(buffer)

            def write_csv(values):
                buffer.seek(0)
                buffer.truncate()
                values = [str(value) for value in values]
                writer.writerow([
                    "'" + value if value.strip().startswith(tuple(CSV_FILE_ESCAPE_CHARS)) else value
                    for value in values
                ])
                output.write(buffer.getvalue().encode('utf-8'))

            write_csv(EXPORT_HEADERS)
            for row in rows:
                write_csv(row)
                count += 1
            content_type = 'text/csv; charset=utf-8'
        else:
            workbook = Workbook(write_only=True)

            def new_sheet():
                sheet = workbook.create_sheet()
                sheet.freeze_panes = 'A2'
                write_excel(sheet, EXPORT_HEADERS)
                return sheet

            def write_excel(sheet, values):
                cells = []
                for value in values:
                    cell = WriteOnlyCell(sheet, value=ILLEGAL_CHARACTERS_RE.sub('', str(value)))
                    cell.data_type = 's'
                    cells.append(cell)
                sheet.append(cells)

            sheet = new_sheet()
            for row in rows:
                if count and count % (EXCEL_SHEET_ROWS - 1) == 0:
                    sheet = new_sheet()
                write_excel(sheet, row)
                count += 1
            workbook.save(output)
            content_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        output.seek(0)
        suffix = timezone.localtime().strftime('%Y-%m-%d_%H-%M-%S')
        response = FileResponse(
            output, as_attachment=True,
            filename=f'user_authorization_{suffix}.{file_format}', content_type=content_type,
        )
        return response, count
    except Exception:
        output.close()
        raise


class UserAuthorizationViewSet(OrgReadonlyModelViewSet):
    model = UserAuthorization
    perm_model = UserAuthorization
    serializer_class = UserAuthorizationSerializer
    filterset_fields = ['username', 'name']
    search_fields = ['username', 'name']
    ordering_fields = ['username', 'name']
    ordering = ['username', 'id']
    page_default_limit = 15
    rbac_perms = {
        'rules': 'audits.view_userauthorization',
        'assets': 'audits.view_userauthorization',
    }

    def get_queryset(self):
        permissions = valid_permissions()
        group_ids = permissions.filter(user_groups__org_id=F('org_id')).values('user_groups')
        return UserAuthorization.get_org_users().filter(
            Q(id__in=permissions.values('users')) | Q(groups__in=group_ids)
        ).distinct().only('id', 'username', 'name')

    def get_serializer_class(self):
        action_name = getattr(self, 'action_map', {}).get('get', self.action)
        return {
            'rules': AuthorizationRuleSerializer,
            'assets': AuthorizationAssetSerializer,
        }.get(action_name, UserAuthorizationSerializer)

    def list(self, request, *args, **kwargs):
        file_format = request.query_params.get('format')
        if file_format not in ('csv', 'xlsx'):
            return super().list(request, *args, **kwargs)
        users = self.filter_queryset(self.get_queryset())
        response, count = export_authorizations(authorization_rows(users), file_format)
        LogMixin().record_logs(request, self, range(count))
        return response

    def _get_user(self):
        user = get_object_or_404(self.get_queryset(), pk=self.kwargs['pk'])
        self.check_object_permissions(self.request, user)
        return user

    def _page(self, queryset):
        page = self.paginator.paginate_queryset(queryset, self.request, view=self)
        if page is not None:
            return self.paginator.get_paginated_response(self.get_serializer(page, many=True).data)
        return Response(self.get_serializer(queryset, many=True).data)

    @action(detail=True, methods=['get'], renderer_classes=[JSONRenderer])
    def rules(self, request, pk=None):
        return self._page(permissions_for_user(self._get_user()).order_by('name', 'id'))

    @action(detail=True, methods=['get'], renderer_classes=[JSONRenderer])
    def assets(self, request, pk=None):
        rule_id = serializers.UUIDField().run_validation(request.query_params.get('rule_id'))
        permission = get_object_or_404(permissions_for_user(self._get_user()), pk=rule_id)
        nodes = Node.objects.filter(org_id=permission.org_id).only('id', 'org_id', 'full_value')
        assets = permission_assets(permission).prefetch_related(Prefetch('nodes', queryset=nodes))
        return self._page(assets)
