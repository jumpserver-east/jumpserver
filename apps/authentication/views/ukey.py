from django.contrib.auth import logout as auth_logout
from django.shortcuts import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import TemplateView
from django.views.generic.edit import FormView

from common.permissions import IsValidUser
from common.utils import FlashMessageUtil, get_logger
from common.views.mixins import PermissionsMixin
from .utils import redirect_to_guard_view
from .. import errors, forms, mixins
from ..mfa.usbkey import MFAUSBKey

logger = get_logger(__name__)
__all__ = ["UserUKeyBindView", "UserUKeyDisableView"]


class UserUKeyBindView(mixins.AuthMixin, TemplateView):
    template_name = "authentication/bind_ukey.html"

    def get(self, request, *args, **kwargs):
        try:
            self.get_user_from_session()
        except errors.SessionEmptyError:
            return redirect_to_guard_view('session_empty')
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        user_id = kwargs.get("user_id", "")
        context = {"user_id": user_id}
        kwargs.update(context)
        return super().get_context_data(**kwargs)


class UserUKeyDisableView(PermissionsMixin, FormView):
    template_name = "authentication/verify_ukey.html"
    form_class = forms.UserCheckOtpCodeForm
    permission_classes = [IsValidUser]

    def form_valid(self, form):
        ukey = MFAUSBKey(self.request.user)
        ukey.set_request(self.request)
        ok, error = ukey.check_code(form.cleaned_data.get('code'))
        if not ok:
            form.add_error('code', error)
            return super().form_invalid(form)

        self.request.user.user_usb_key.all().delete()
        auth_logout(self.request)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        ukey = MFAUSBKey(self.request.user)
        context.update({
            'title': _("Disable USBKey"),
            'mfa_backends': [ukey],
        })
        return context

    def get_success_url(self):
        message_data = {
            'title': _('USBKey disable success'),
            'message': _('USBKey disable success, return login page'),
            'interval': 5,
            'redirect_url': reverse('authentication:login'),
        }
        url = FlashMessageUtil.gen_message_url(message_data)
        return url
