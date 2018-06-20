from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.functional import lazy
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from talos.forms import BasicLoginForm
from talos.forms import BasicPasswordChangeConfirmForm
from talos.forms import BasicPasswordResetRequestForm
from talos.forms import BasicPasswordResetConfirmForm
from talos.forms import EmailChangeConfirmForm
from talos.forms import EmailChangeRequestForm
from talos.forms import PrincipalRegistrationConfirmForm
from talos.forms import PrincipalRegistrationRequestForm

from rest_framework.generics import GenericAPIView
from rest_framework.views import  APIView



from talos_test_app.authentication import CsrfExemptSessionAuthentication

# Serializer classes
from talos_test_app.serializers import BasicLoginSerializer
from talos_test_app.serializers import PrincipalRegistrationRequestSerializer
from talos_test_app.serializers import PrincipalRegistrationConfirmSerializer

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


class SecureFormViewBaseView(TranslationContextMixin, GenericAPIView):


    def get_serializer_context(self):
        from talos.models import _tznow
        from talos.models import ValidationToken

        kwargs = super(SecureFormViewBaseView, self).get_serializer_context()
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
                #kwargs['initial'].update({'new_email': token.email})
            except ValidationToken.DoesNotExist:
                kwargs['token'] = None

        kwargs['request'] = self.request._request

        return kwargs

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        return super(SecureFormViewBaseView, self).dispatch(request, *args, **kwargs)


class BasicLoginAPIView(SecureFormViewBaseView):   
    identity_directory_code = 'basic_internal'

    serializer_class = BasicLoginSerializer
    #
    def get(self, request, *args, **kwargs):
        return Response({"user":str(request.principal)})


    def post(self, request, *args, **kwargs):
        kwargs = super(BasicLoginAPIView, self).get_serializer_context()
        data = request.data
        serializer = BasicLoginSerializer(data = data, context=kwargs)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            session_id = self.request.session._session.uuid
            return Response({"Success": session_id})
        else:
            return Response({"Success": "NO"})





class PrincipalRegistrationRequestEditAPIView(SecureFormViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PrincipalRegistrationRequestSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text" : "user registration request"})

    def post(self, request, *args, **kwargs):
        kwargs = super(PrincipalRegistrationRequestEditAPIView, self).get_serializer_context()
        data = request.data
        serializer = PrincipalRegistrationRequestSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text" : "registration url has been sent on your email"})
        else:
            return Response({"error" : dict(serializer.errors.items())})




class PrincipalRegistrationConfirmationAPIView(SecureFormViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PrincipalRegistrationConfirmSerializer
    token_type = 'principal_registration'

    def get(self, request, *args, **kwargs):
        return Response({"text" : "user registration confirmation"})

    def post(self, request, *args, **kwargs):
        kwargs = super(PrincipalRegistrationConfirmationAPIView, self).get_serializer_context()
        data = request.data
        serializer = PrincipalRegistrationConfirmSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text" : "registration url has"})
        else:
            return Response({"text" : "error"})
