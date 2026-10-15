from django.conf import settings
from django.views.generic import TemplateView
from django.views.generic.edit import FormView

from common.utils import get_logger
from .utils import redirect_to_guard_view
from .. import forms, errors, mixins

logger = get_logger(__name__)
__all__ = ["UserUKeyView", "UserUKeyBindView"]


class UserUKeyView(mixins.AuthMixin, FormView):
    template_name = "authentication/login_ukey_verify.html"
    form_class = forms.UserUKeyForm
    redirect_field_name = "next"

    def get(self, *args, **kwargs):
        try:
            self.get_user_from_session()
        except errors.SessionEmptyError:
            return redirect_to_guard_view("session_empty")
        return super().get(*args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # 验签后端决定浏览器端用裸签（piico）还是 detached P7（cpas）；userID 须与平台 U013 入参一致
        cpas_enabled = settings.UKEY_CPAS_ENABLED
        context["ukey_verify_backend"] = "cpas" if cpas_enabled else "piico"
        context["ukey_user_id"] = settings.CPAS_UKEY_USER_ID if cpas_enabled else "1234567812345678"
        return context

    def form_valid(self, form):
        ukey_token = form.cleaned_data.get("token")
        try:
            user = self.get_user_from_session()
            self.check_ukey_auth(user, ukey_token)
            return redirect_to_guard_view("ukey_ok")
        except (errors.UKeyUnsetError, errors.LoginCheckKeyError) as e:
            form.add_error("token", e.msg)
            return super().form_invalid(form)
        except errors.SessionEmptyError:
            return redirect_to_guard_view("session_empty")
        except Exception as e:
            logger.error(e, exc_info=True)
            return redirect_to_guard_view("unexpect")


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
