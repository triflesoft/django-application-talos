from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.functional import lazy
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.edit import FormView
from django.views.generic.base import TemplateView
from django.views import View

from .forms import BasicLoginForm
from .forms import BasicPasswordChangeConfirmForm
from .forms import BasicPasswordResetRequestForm
from .forms import BasicPasswordResetConfirmForm
from .forms import EmailChangeConfirmForm
from .forms import EmailChangeRequestForm
from .forms import PrincipalRegistrationConfirmForm
from .forms import PrincipalRegistrationRequestForm


class TranslationContextMixin(object):
    def get_context_data(self, **kwargs):
        context = super(TranslationContextMixin, self).get_context_data(**kwargs)

        context['translations'] = {
            'home_link': 'Home',
            'principal_register_link': 'Register Principal',
            'principal_email_change_link': 'Change E-mail',
            'logout_link': 'Log out',
            'basic_login_link': 'Log in',
            'basic_password_reset_link': 'Reset Password',
            'basic_password_change_link': 'Change Password',
            'process': getattr(self, 'process', None),
            'step_header': getattr(self, 'step_header', None),
            'step_summary': getattr(self, 'step_summary', None),
            'step_message': getattr(self, 'step_message', None),
            'submit': getattr(self, 'submit', None),
        }

        return context


class SecureFormViewBaseView(TranslationContextMixin, FormView):
    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        return super(SecureFormViewBaseView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        from .models import _tznow
        from .models import ValidationToken

        kwargs = super(SecureFormViewBaseView, self).get_form_kwargs()
        identity_directory_code = getattr(self, 'identity_directory_code', None)

        if identity_directory_code:
            kwargs['identity_directory_code'] = identity_directory_code

        token_type = getattr(self, 'token_type', None)

        if token_type:
            try:
                token = ValidationToken.objects.get(
                    secret=self.kwargs['secret'],
                    type=token_type,
                    expires_at__gt=_tznow(),
                    is_active=True)
                kwargs['token'] = token
                kwargs['initial'].update({'new_email': token.email})
            except ValidationToken.DoesNotExist:
                kwargs['token'] = None

        kwargs['request'] = self.request

        return kwargs


class SecureTemplateViewBaseView(TranslationContextMixin, TemplateView):
    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        return super(SecureTemplateViewBaseView, self).dispatch(request, *args, **kwargs)


class IndexView(SecureTemplateViewBaseView):
    process = 'Authentication'
    step_header = 'Authentication'
    step_summary = lazy(lambda slf: 'You are logged in as {0} ({1})'.format(slf.request.principal.full_name, slf.request.principal.email), str)
    template_name = 'talos/index.html'

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)

        context['principal'] = self.request.principal

        return context


class PrincipalRegistrationRequestEditView(SecureFormViewBaseView):
    process = 'Principal Registration'
    step_header = 'Principal Registration Request'
    step_summary = 'Please, provide your e-mail'
    submit = 'Send instructions to e-mail'
    form_class = PrincipalRegistrationRequestForm
    template_name = 'talos/principal_registration/request_edit.html'

    def form_valid(self, form):
        from django.http import HttpResponseRedirect
        from django.urls import reverse

        form.save()

        return HttpResponseRedirect(reverse('talos-principal-registration-request-done'))


class PrincipalRegistrationRequestDoneView(SecureTemplateViewBaseView):
    process = 'Principal Registration'
    step_header = 'Principal Registration Request'
    step_summary = 'E-mail with further instructions has been sent.'
    step_message = 'Please, check your e-mail inbox. Make sure request was not caught by spam filter.'
    template_name = 'talos/principal_registration/request_done.html'


class PrincipalRegistrationConfirmEditView(SecureFormViewBaseView):
    process = 'Principal Registration'
    step_header = 'Principal Registration Confirm'
    step_summary = 'Please, provide your registration information'
    submit = 'Confirm registration'
    identity_directory_code = 'basic_internal'
    token_type = 'principal_registration'
    form_class = PrincipalRegistrationConfirmForm
    template_name = 'talos/principal_registration/confirm_edit.html'

    def form_valid(self, form):
        from django.http import HttpResponseRedirect
        from django.urls import reverse

        form.save()

        return HttpResponseRedirect(reverse('talos-principal-registration-confirm-done'))


class PrincipalRegistrationConfirmDoneView(SecureTemplateViewBaseView):
    process = 'Principal Registration'
    step_header = 'Principal Registration Confirm'
    step_summary = 'You have successfully registered a principal'
    step_message = lazy(lambda slf: 'Now, you can <a class="button is-small is-info"  href="{0}">log in</a>.'.format(reverse('talos-basic-login')), str)
    template_name = 'talos/principal_registration/confirm_done.html'


class EmailChangeRequestEditView(SecureFormViewBaseView):
    process = 'E-mail Change'
    step_header = 'E-mail Change Request'
    step_summary = 'Please, provide your new e-mail'
    submit = 'Send instructions to new e-mail'
    form_class = EmailChangeRequestForm
    template_name = 'talos/email_change/request_edit.html'

    def form_valid(self, form):
        from django.http import HttpResponseRedirect
        from django.urls import reverse

        form.save()

        return HttpResponseRedirect(reverse('talos-email-change-request-done'))


class EmailChangeRequestDoneView(SecureTemplateViewBaseView):
    process = 'E-mail Change'
    step_header = 'E-mail Change Request'
    step_summary = 'E-mail with further instructions has been sent.'
    step_message = 'Please, check your e-mail inbox. Make sure request was not caught by spam filter.'
    template_name = 'talos/email_change/request_done.html'


class EmailChangeConfirmEditView(SecureFormViewBaseView):
    process = 'E-mail Change'
    step_header = 'E-mail Change Confirm'
    step_summary = 'Please, confirm your new e-mail'
    submit = 'Confirm e-mail change'
    token_type = 'email_change'
    form_class = EmailChangeConfirmForm
    template_name = 'talos/email_change/confirm_edit.html'

    def form_valid(self, form):
        from django.http import HttpResponseRedirect
        from django.urls import reverse

        form.save()

        return HttpResponseRedirect(reverse('talos-email-change-confirm-done'))


class EmailChangeConfirmDoneView(SecureTemplateViewBaseView):
    process = 'E-mail Change'
    step_header = 'E-mail Change Confirm'
    step_summary = 'You have successfully changed e-mail'
    step_message = 'You cannot use your old e-mail anymore.'
    template_name = 'talos/email_change/confirm_done.html'


class LogoutView(SecureTemplateViewBaseView):
    process = 'Log out'
    step_header = 'Log out'
    step_summary = 'You have successfully logged out'
    step_message = lazy(lambda slf: 'You are not authenticated anymore. Try to <a class="button is-small is-info" href="{0}">log in</a> again.'.format(reverse('talos-basic-login')), str)
    template_name = 'talos/logout/index.html'

    def get_context_data(self, **kwargs):
        context = super(LogoutView, self).get_context_data(**kwargs)

        old_principal = self.request.principal
        self.request.session.flush()

        context['old_principal'] = old_principal

        return context


class BasicLoginView(SecureFormViewBaseView):
    process = 'Basic Login'
    step_header = 'Login'
    step_summary = 'Please, provide your username and password'
    submit = 'Log in'
    identity_directory_code = 'basic_internal'
    form_class = BasicLoginForm
    template_name = 'talos/basic_login/index.html'

    def form_valid(self, form):
        from django.conf import settings
        from django.contrib.auth import REDIRECT_FIELD_NAME
        from django.http import HttpResponseRedirect

        form.save()

        redirect_url = self.request.GET.get(REDIRECT_FIELD_NAME, settings.LOGIN_REDIRECT_URL)

        return HttpResponseRedirect(redirect_url)


class BasicPasswordChangeConfirmEditView(SecureFormViewBaseView):
    process = 'Password Change'
    step_header = 'Password Change Confirm'
    step_summary = 'Please, provide old password and new password'
    submit = 'Confirm password change'
    identity_directory_code = 'basic_internal'
    form_class = BasicPasswordChangeConfirmForm
    template_name = 'talos/basic_password_change/confirm_edit.html'

    def form_valid(self, form):
        from django.http import HttpResponseRedirect
        from django.urls import reverse

        form.save()

        return HttpResponseRedirect(reverse('talos-basic-password-change-done'))


class BasicPasswordChangeConfirmDoneView(SecureTemplateViewBaseView):
    process = 'Password Change'
    step_header = 'Password Change Confirm'
    step_summary = 'You have successfully changed password'
    step_message = 'You cannot use your old password anymore.'
    template_name = 'talos/basic_password_change/confirm_done.html'


class BasicPasswordResetRequestEditView(SecureFormViewBaseView):
    process = 'Password Reset'
    step_header = 'Password Reset Request'
    step_summary = 'Please, provide your e-mail'
    submit = 'Send instructions to e-mail'
    form_class = BasicPasswordResetRequestForm
    template_name = 'talos/basic_password_reset/request_edit.html'

    def form_valid(self, form):
        from django.http import HttpResponseRedirect
        from django.urls import reverse

        form.save()

        return HttpResponseRedirect(reverse('talos-basic-password-reset-request-done'))


class BasicPasswordResetRequestDoneView(SecureTemplateViewBaseView):
    process = 'Password Reset'
    step_header = 'Password Reset Request'
    step_summary = 'E-mail with further instructions has been sent.'
    step_message = 'Please, check your e-mail inbox. Make sure request was not caught by spam filter.'
    template_name = 'talos/basic_password_reset/request_done.html'


class BasicPasswordResetConfirmEditView(SecureFormViewBaseView):
    process = 'Password Reset'
    step_header = 'Password Reset Confirm'
    step_summary = 'Please, provide new password'
    submit = 'Confirm password reset'
    identity_directory_code = 'basic_internal'
    token_type = 'password_reset'
    form_class = BasicPasswordResetConfirmForm
    template_name = 'talos/basic_password_reset/confirm_edit.html'

    def form_valid(self, form):
        from django.http import HttpResponseRedirect
        from django.urls import reverse

        form.save()

        return HttpResponseRedirect(reverse('talos-basic-password-reset-confirm-done'))


class BasicPasswordResetConfirmDoneView(SecureTemplateViewBaseView):
    process = 'Password Reset'
    step_header = 'Password Reset Confirm'
    step_summary = 'You have successfully reset your password'
    step_message = lazy(lambda slf: 'Now, you can <a class="button is-small is-info" href="{0}">log in</a> again.'.format(reverse('talos-basic-login')), str)
    template_name = 'talos/basic_password_reset/confirm_done.html'


class TokenLoginView(View):
    def __init__(self, *args, **kwargs):
        from .models import TokenCredentialDirectory
        from re import compile

        token_directories = []

        for token_credential_directory in TokenCredentialDirectory.objects.all().prefetch_related('options', 'provided_evidences'):
            pattern = token_credential_directory.get('HTTP_AUTHORIZATION_HEADER_VALUE_PATTERN', None)

            if pattern:
                token_directories.append((
                    compile(pattern),
                    token_credential_directory,
                    list(token_credential_directory.provided_evidences.all())))

        self.token_directories = token_directories

        return super(TokenLoginView, self).__init__(*args, **kwargs)

    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        return super(TokenLoginView, self).dispatch(request, *args, **kwargs)

    def get(self, request):
        from .models import _tznow
        from .models import TokenCredential
        from django.http import HttpResponse
        from django.http import HttpResponseForbidden

        authorization = request.META.get('HTTP_AUTHORIZATION', None)

        if authorization:
            now = _tznow()

            for token_directory in self.token_directories:
                match = token_directory[0].match(authorization)

                if match:
                    token_value = match.group('value')

                    try:
                        token_credential = TokenCredential.objects.get(
                            directory=token_directory[1],
                            public_value=token_value,
                            valid_from__lte=now,
                            valid_till__gte=now)

                        principal = token_credential.principal
                        principal._load_authentication_context(token_directory[2])
                        request.principal = principal

                        return HttpResponse()
                    except TokenCredential.DoesNotExist:
                        pass

        return HttpResponseForbidden()
