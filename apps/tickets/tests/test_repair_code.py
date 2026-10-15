from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch
from types import SimpleNamespace

from django.core.cache import cache
from django.core import mail
from django.core.mail import get_connection
from django.db import connections, transaction
from django.test import TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.test import APIRequestFactory, force_authenticate

from assets.models import Asset, Platform
from common.exceptions import JMSException
from notifications.backends import BACKEND
from notifications.notifications import Message
from orgs.models import Organization
from orgs.utils import tmp_to_org
from perms.const import ActionChoices
from perms.models import AssetPermission
from tickets.api.ticket import ApplyAssetTicketViewSet, RepairCodeThrottle
from tickets.const import TicketState, TicketStatus
from tickets.models import ApplyAssetTicket, ApprovalRule, TicketFlow, TicketRepairCode
from tickets.notifications import TicketAppliedToAssigneeMessage, TicketUpdatedToCcUserMessage
from tickets.repair_codes import code_digest, issue_repair_codes, redeem_repair_code
from tickets.serializers import ApplyAssetSerializer, RepairCodeSerializer, TicketSerializer
from users.models import User


@override_settings(EMAIL_HOST='mail.example.test')
class RepairCodeTestCase(TestCase):
    def setUp(self):
        self.org = Organization.default()
        self.org_context = tmp_to_org(self.org)
        self.org_context.__enter__()
        self.addCleanup(self.org_context.__exit__, None, None, None)
        self.applicant = User.objects.create(username='repair-applicant', name='Applicant')
        self.approver = User.objects.create(username='repair-approver', email='approver@example.test')
        self.other = User.objects.create(username='repair-other', email='other@example.test')
        platform = Platform.objects.create(name='repair-test-platform')
        self.asset = Asset.objects.create(name='requested', address='192.0.2.10', platform=platform)
        self.unrequested_asset = Asset.objects.create(name='unrequested', address='192.0.2.11', platform=platform)
        self.ticket = ApplyAssetTicket.objects.create(
            title='Repair request', applicant=self.applicant, org_id=self.org.id,
            apply_permission_name='Repair permission', apply_accounts=['root'],
            apply_actions=ActionChoices.connect,
            apply_date_start=timezone.now() - timedelta(minutes=1),
            apply_date_expired=timezone.now() + timedelta(hours=1),
        )
        self.ticket.apply_assets.add(self.asset)
        self.ticket.create_process_steps_by_assignees([self.approver, self.other])
        self.ticket.set_rel_snapshot()
        self.credential = TicketRepairCode.objects.create(
            ticket=self.ticket, approver=self.approver,
            digest=code_digest(self.applicant.id, '012345'),
        )

    def test_redeem_grants_only_requested_scope_and_consumes_all_codes(self):
        TicketRepairCode.objects.create(
            ticket=self.ticket, approver=self.other,
            digest=code_digest(self.applicant.id, '654321'),
        )
        ticket = redeem_repair_code(self.applicant, '012345')
        self.assertEqual(ticket.state, TicketState.approved)
        self.assertEqual(ticket.status, TicketStatus.closed)
        permission = AssetPermission.objects.get(id=self.ticket.id)
        self.assertEqual(list(permission.users.all()), [self.applicant])
        self.assertEqual(list(permission.assets.all()), [self.asset])
        self.assertEqual(permission.accounts, ['root'])
        self.assertEqual(permission.actions, ActionChoices.connect)
        self.assertEqual(permission.date_start, self.ticket.apply_date_start)
        self.assertEqual(permission.date_expired, self.ticket.apply_date_expired)
        self.assertFalse(ticket.repair_codes.filter(used_at__isnull=True).exists())
        for code in ['012345', '654321']:
            with self.assertRaises(ValidationError):
                redeem_repair_code(self.applicant, code)
        self.assertEqual(AssetPermission.objects.filter(id=ticket.id).count(), 1)
        self.assertTrue(ticket.comments.filter(user=self.applicant, body__contains='repair code').exists())

    def test_wrong_code_and_other_user_do_not_grant(self):
        for user, code in [(self.applicant, '999999'), (self.other, '012345')]:
            with self.assertRaises(ValidationError):
                redeem_repair_code(user, code)
        self.assertFalse(AssetPermission.objects.filter(id=self.ticket.id).exists())
        self.credential.refresh_from_db()
        self.assertIsNone(self.credential.used_at)

    def test_closed_rejected_and_expired_tickets_cannot_be_redeemed(self):
        for state in [TicketState.closed, TicketState.rejected]:
            ApplyAssetTicket.objects.filter(pk=self.ticket.pk).update(state=state, status=TicketStatus.closed)
            with self.assertRaises(ValidationError):
                redeem_repair_code(self.applicant, '012345')
        ApplyAssetTicket.objects.filter(pk=self.ticket.pk).update(
            state=TicketState.pending, status=TicketStatus.open,
            apply_date_expired=timezone.now() - timedelta(seconds=1),
        )
        with self.assertRaises(ValidationError):
            redeem_repair_code(self.applicant, '012345')
        self.assertFalse(AssetPermission.objects.filter(id=self.ticket.id).exists())

    def test_deleted_requested_assets_do_not_complete_ticket(self):
        self.ticket.apply_assets.clear()
        with self.assertRaises(ValidationError):
            redeem_repair_code(self.applicant, '012345')
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.state, TicketState.pending)

    def test_failed_user_binding_rolls_back_permission_ticket_and_code(self):
        manager_class = AssetPermission.users.related_manager_cls
        with patch.object(manager_class, 'add', side_effect=RuntimeError('binding failed')):
            with self.assertRaises(RuntimeError):
                redeem_repair_code(self.applicant, '012345')
        self.ticket.refresh_from_db()
        self.credential.refresh_from_db()
        self.assertEqual(self.ticket.state, TicketState.pending)
        self.assertIsNone(self.credential.used_at)
        self.assertFalse(AssetPermission.objects.filter(id=self.ticket.id).exists())

    def test_direct_approval_is_disabled(self):
        with self.assertRaises(JMSException):
            self.ticket.approve(self.approver)
        self.assertFalse(AssetPermission.objects.filter(id=self.ticket.id).exists())

    def test_only_first_flow_level_receives_codes_after_commit(self):
        flow = TicketFlow.objects.create(name='Two levels', type='apply_asset', approval_level=2)
        flow.rules.add(ApprovalRule.objects.create(level=1), ApprovalRule.objects.create(level=2))
        self.ticket.ticket_steps.all().delete()
        self.ticket.repair_codes.all().delete()
        self.ticket.flow = flow
        with patch.object(ApprovalRule, 'get_assignees', return_value=[self.approver, self.other]) as get_assignees:
            self.ticket.create_process_steps_by_flow()
        get_assignees.assert_called_once_with(org_id=self.ticket.org_id)
        self.assertEqual(self.ticket.ticket_steps.count(), 1)
        with patch.object(TicketAppliedToAssigneeMessage, 'publish_async', autospec=True) as publish:
            with self.captureOnCommitCallbacks(execute=True):
                issue_repair_codes(self.ticket, self.ticket.current_assignees)
                publish.assert_not_called()
            self.assertEqual(publish.call_count, 2)
            self.assertEqual({c.args[0].user.id for c in publish.call_args_list}, {self.approver.id, self.other.id})
            for call in publish.call_args_list:
                self.assertRegex(call.args[0].repair_code, r'^[0-9]{6}$')

    def test_collision_does_not_bind_code_to_another_ticket(self):
        with patch('tickets.repair_codes.secrets.randbelow', side_effect=[12345, 543210]):
            issue_repair_codes(self.ticket, [self.other])
        new_code = TicketRepairCode.objects.get(digest=code_digest(self.applicant.id, '543210'))
        self.assertEqual(new_code.approver_id, self.other.id)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.approver_id, self.approver.id)

    def test_email_contains_code_without_direct_approval_or_other_channel_leak(self):
        message = TicketAppliedToAssigneeMessage(self.approver, self.ticket, repair_code='012345')
        messages = message.get_backend_msg_mapper([BACKEND.SITE_MSG])
        self.assertIn(BACKEND.EMAIL, messages)
        self.assertIn('012345', messages[BACKEND.EMAIL]['message'])
        self.assertNotIn('012345', messages[BACKEND.SITE_MSG]['message'])
        self.assertIsNone(message.get_ticket_approval_url())
        cc_message = TicketUpdatedToCcUserMessage(self.other, self.ticket).get_html_msg()['message']
        self.assertNotIn('012345', cc_message)
        self.assertNotIn(self.credential.digest, str(TicketSerializer(self.ticket).data))

    def test_email_is_delivered_to_approver_through_existing_mail_backend(self):
        message = TicketAppliedToAssigneeMessage(self.approver, self.ticket, repair_code='012345')
        with patch('common.tasks.get_email_connection', return_value=get_connection('django.core.mail.backends.locmem.EmailBackend')):
            Message.send_msg([self.approver.id], {BACKEND.EMAIL: message.get_email_msg()})
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [self.approver.email])
        self.assertIn('012345', mail.outbox[0].body)

    def make_application_serializer(self, **overrides):
        flow = TicketFlow.objects.create(name='Application flow', type='apply_asset')
        flow.rules.add(ApprovalRule.objects.create(level=1))
        data = {
            'title': 'Complete application', 'org_id': str(self.org.id), 'flow_id': str(flow.id),
            'apply_assets': [str(self.asset.id)], 'apply_accounts': ['root'],
            'apply_actions': ['connect'],
            'apply_date_start': timezone.now(), 'apply_date_expired': timezone.now() + timedelta(hours=1),
        }
        data.update(overrides)
        return ApplyAssetSerializer(data=data, context={'request': SimpleNamespace(user=self.applicant)})

    def test_full_application_emails_after_commit_then_grants_on_redemption(self):
        serializer = self.make_application_serializer()
        with patch.object(ApprovalRule, 'get_assignees', return_value=[self.approver]):
            self.assertTrue(serializer.is_valid(), serializer.errors)
            with patch('tickets.repair_codes.secrets.randbelow', return_value=135790):
                with patch('notifications.notifications.publish_task.delay') as publish:
                    with self.captureOnCommitCallbacks(execute=True):
                        ApplyAssetTicketViewSet().perform_create(serializer)
                        publish.assert_not_called()
                    self.assertEqual(publish.call_count, 1)
                    recipients, messages = publish.call_args.args
                    self.assertEqual(recipients, [self.approver.id])
                    self.assertIn('135790', messages[BACKEND.EMAIL]['message'])
                    self.assertNotIn('135790', messages[BACKEND.SITE_MSG]['message'])
        self.assertFalse(AssetPermission.objects.filter(id=serializer.instance.id).exists())
        ticket = redeem_repair_code(self.applicant, '135790')
        self.assertEqual(ticket.id, serializer.instance.id)
        self.assertTrue(AssetPermission.objects.get(id=ticket.id).users.filter(id=self.applicant.id).exists())

    def test_request_requires_complete_scope_and_approver_email(self):
        for missing in [{'apply_assets': []}, {'apply_accounts': []}]:
            serializer = self.make_application_serializer(**missing)
            with patch.object(ApprovalRule, 'get_assignees', return_value=[self.approver]):
                self.assertFalse(serializer.is_valid())
        self.approver.email = ''
        serializer = self.make_application_serializer()
        with patch.object(ApprovalRule, 'get_assignees', return_value=[self.approver]):
            self.assertFalse(serializer.is_valid())
            self.assertIn('flow_id', serializer.errors)

    @override_settings(EMAIL_HOST='')
    def test_request_fails_before_creation_if_mail_is_not_configured(self):
        serializer = self.make_application_serializer()
        self.assertFalse(serializer.is_valid())
        self.assertIn('email server', str(serializer.errors))

    def test_code_format_preserves_leading_zero_and_rejects_non_digits(self):
        for code in ['12345', '1234567', '１２３４５６', '123456\n', ' 123456']:
            self.assertFalse(RepairCodeSerializer(data={'code': code}).is_valid())
        serializer = RepairCodeSerializer(data={'code': '012345'})
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['code'], '012345')

    def api_request(self, code, user=None):
        request = APIRequestFactory().post('/redeem-code/', {'code': code}, format='json')
        if user:
            force_authenticate(request, user)
        with transaction.atomic():
            return ApplyAssetTicketViewSet.as_view(
                {'post': 'redeem_code'}, permission_classes=[IsAuthenticated],
                throttle_classes=[],
            )(request)

    def test_api_requires_login_and_ownership(self):
        self.assertIn(self.api_request('012345').status_code, [401, 403])
        self.assertEqual(self.api_request('012345', self.other).status_code, 400)
        with patch.object(ApplyAssetTicketViewSet, '_record_operate_log'):
            response = self.api_request('012345', self.applicant)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['id'], str(self.ticket.id))
        self.assertEqual(response.data['state'], 'approved')

    def test_code_verification_is_rate_limited_per_applicant(self):
        request = APIRequestFactory().post('/redeem-code/')
        request.user = self.applicant
        throttle = RepairCodeThrottle()
        key = throttle.get_cache_key(request, None)
        self.addCleanup(cache.delete, key)
        for _ in range(5):
            self.assertTrue(RepairCodeThrottle().allow_request(request, None))
        self.assertFalse(RepairCodeThrottle().allow_request(request, None))


@override_settings(EMAIL_HOST='mail.example.test')
class RepairCodeConcurrencyTestCase(TransactionTestCase):
    setUp = RepairCodeTestCase.setUp

    @skipUnlessDBFeature('has_select_for_update')
    def test_concurrent_redemptions_grant_once(self):
        barrier = Barrier(2)

        def redeem():
            try:
                user = User.objects.get(pk=self.applicant.pk)
                barrier.wait(timeout=10)
                try:
                    redeem_repair_code(user, '012345')
                    return 'granted'
                except ValidationError:
                    return 'rejected'
            finally:
                connections.close_all()

        with patch('notifications.notifications.publish_task.delay'):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: redeem(), range(2)))
        self.assertCountEqual(results, ['granted', 'rejected'])
        self.assertEqual(AssetPermission.objects.filter(id=self.ticket.id).count(), 1)
        self.credential.refresh_from_db()
        self.assertIsNotNone(self.credential.used_at)
