from django.db import models
from django.utils.translation import gettext_lazy as _

from common.exceptions import JMSException
from perms.const import ActionChoices
from tickets.const import TicketType
from .general import Ticket, TicketStep, TicketAssignee

__all__ = ['ApplyAssetTicket']

asset_or_node_help_text = _("Select at least one asset or node")


class ApplyAssetTicket(Ticket):
    apply_permission_name = models.CharField(max_length=128, verbose_name=_('Permission name'))
    apply_nodes = models.ManyToManyField('assets.Node', verbose_name=_('Node'))
    # 申请信息
    apply_assets = models.ManyToManyField('assets.Asset', verbose_name=_('Asset'))
    apply_accounts = models.JSONField(default=list, verbose_name=_('Apply accounts'))
    apply_actions = models.IntegerField(verbose_name=_('Actions'), default=ActionChoices.connect)
    apply_date_start = models.DateTimeField(verbose_name=_('Date start'), null=True)
    apply_date_expired = models.DateTimeField(verbose_name=_('Date expired'), null=True)

    TICKET_TYPE = TicketType.apply_asset

    def create_process_steps_by_flow(self):
        rule = self.flow.rules.order_by('level').first()
        assignees = self.exclude_applicant(
            rule.get_assignees(org_id=self.org_id), self.applicant
        )
        step = TicketStep.objects.create(ticket=self, level=1)
        TicketAssignee.objects.bulk_create([
            TicketAssignee(step=step, assignee=user) for user in assignees
        ])

    def approve(self, processor):
        raise JMSException(
            _('Asset requests must be authorized by the applicant using a repair code.'),
            code='repair_code_required'
        )

    def get_apply_actions_display(self):
        return ActionChoices.display(self.apply_actions)

    class Meta:
        verbose_name = _('Apply Asset Ticket')
