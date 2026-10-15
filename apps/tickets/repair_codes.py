import secrets

from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.crypto import salted_hmac
from django.utils.translation import gettext as _
from rest_framework.exceptions import ValidationError

from orgs.utils import tmp_to_org
from tickets.const import TicketState, TicketStatus
from tickets.models import ApplyAssetTicket, Ticket, TicketRepairCode
from tickets.notifications import TicketAppliedToAssigneeMessage


def code_digest(applicant_id, code):
    return salted_hmac(
        'tickets.repair_code', f'{applicant_id}:{code}', algorithm='sha256'
    ).hexdigest()


def issue_repair_codes(ticket, assignees):
    for approver in assignees:
        for attempt in range(10):
            code = f'{secrets.randbelow(1000000):06d}'
            try:
                with transaction.atomic(savepoint=True):
                    TicketRepairCode.objects.create(
                        ticket=ticket, approver=approver,
                        digest=code_digest(ticket.applicant_id, code)
                    )
                break
            except IntegrityError:
                if attempt == 9:
                    raise
        message = TicketAppliedToAssigneeMessage(approver, ticket, repair_code=code)
        transaction.on_commit(message.publish_async)


@transaction.atomic
def redeem_repair_code(applicant, code):
    digest = code_digest(applicant.id, code)
    candidate = TicketRepairCode.objects.filter(
        digest=digest, ticket__applicant=applicant, used_at__isnull=True
    ).values_list('ticket_id', flat=True).first()
    invalid = _('The repair code is invalid, expired, or already used.')
    if not candidate:
        raise ValidationError({'code': invalid})

    # Lock the ticket first, just like rejection/cancellation, then recheck the code.
    ticket = ApplyAssetTicket.objects.select_for_update().get(pk=candidate)
    credential = ticket.repair_codes.filter(
        digest=digest, used_at__isnull=True
    ).select_related('approver').first()
    if (
        not credential or ticket.applicant_id != applicant.id
        or ticket.state != TicketState.pending or ticket.status != TicketStatus.open
        or not ticket.apply_date_expired or ticket.apply_date_expired <= timezone.now()
        or not ticket.has_current_assignee(credential.approver)
        or ticket.ticket_steps.count() != 1
    ):
        raise ValidationError({'code': invalid})

    with tmp_to_org(ticket.org_id):
        if not (ticket.apply_assets.exists() or ticket.apply_nodes.exists()) or not ticket.apply_accounts:
            raise ValidationError(_(
                'The requested assets or accounts are no longer available. Please apply again.'
            ))
        Ticket.approve(ticket, processor=credential.approver)
        ticket.repair_codes.update(used_at=timezone.now())
        ticket.comments.create(
            user=applicant, user_display=str(applicant),
            body=_('{} entered the repair code to obtain the requested asset permissions.').format(applicant),
        )
    return ticket
