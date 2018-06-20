from django.utils.decorators import method_decorator

from django.views.decorators.cache import never_cache

from django.views.decorators.debug import sensitive_post_parameters

from rest_framework.response import Response
from .utils import SuccessResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView
from rest_framework import status
# Serializer classes
from .exceptions.custom_exceptions import APIValidationError
from talos_test_app.serializers import (SessionSerializer,
                                        PrincipalRegistrationRequestSerializer,
                                        PrincipalRegistrationConfirmSerializer,
                                        PrincipalRegistrationTokenValidationSerializer,
                                        EmailChangeRequestSerializer,
                                        EmailChangeConfirmSerializer,
                                        GoogleAuthenticatorActivateSerializer,
                                        GoogleAuthenticatorVerifySerializer,
                                        GoogleAuthenticatorDeleteSerializer)


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


class SecureAPIViewBaseView(TranslationContextMixin, GenericAPIView):
    def get_serializer_context(self):
        from talos.models import _tznow
        from talos.models import ValidationToken

        kwargs = super(SecureAPIViewBaseView, self).get_serializer_context()
        identity_directory_code = getattr(self, 'identity_directory_code', None)

        if identity_directory_code:
            kwargs['identity_directory_code'] = identity_directory_code

        token_type = getattr(self, 'token_type', None)

        if token_type:
            try:
                token = ValidationToken.objects.get(
                    secret=self.kwargs.get('secret'),
                    type=token_type,
                    expires_at__gt=_tznow(),
                    is_active=True)
                kwargs['token'] = token
            except ValidationToken.DoesNotExist:
                kwargs['token'] = None

        kwargs['request'] = self.request._request

        return kwargs

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        return super(SecureAPIViewBaseView, self).dispatch(request, *args, **kwargs)


class SecureTemplateViewBaseView(TranslationContextMixin, GenericAPIView):
    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        return super(SecureTemplateViewBaseView, self).dispatch(request, *args, **kwargs)


class SessionAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'

    serializer_class = SessionSerializer

    def get(self, request, *args, **kwargs):
        if str(self.request.user) == 'Anonymous':
            # data = SuccessResponse(code=status.HTTP_404_NOT_FOUND)
            success_response = SuccessResponse(code=status.HTTP_404_NOT_FOUND)

        else:
            success_response = SuccessResponse()
            success_response.set_result_pairs('session_id', request.session._session.uuid)

        return Response(data=success_response.data,
                        status=success_response.status)

    def post(self, request, *args, **kwargs):
        kwargs = super(SessionAPIView, self).get_serializer_context()
        data = request.data
        serializer = SessionSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)

    def delete(self, reqest, *args, **kwargs):
        if str(self.request.user) == 'Anonymous':
            success_response = SuccessResponse(code=status.HTTP_404_NOT_FOUND)
        else:
            self.request.session.flush()
            success_response = SuccessResponse()
        return Response(data=success_response.data,
                        status=success_response.status)


class PrincipalRegistrationRequestEditAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PrincipalRegistrationRequestSerializer

    def post(self, request, *args, **kwargs):
        kwargs = super(PrincipalRegistrationRequestEditAPIView, self).get_serializer_context()
        data = request.data
        serializer = PrincipalRegistrationRequestSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            token = serializer.validation_token
            data = {'token': str(token)}
            data.update(serializer.data)
            return Response(data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PrincipalRegistrationTokenValidationAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PrincipalRegistrationTokenValidationSerializer

    def get(self, request, *args, **kwargs):

        serializer = PrincipalRegistrationTokenValidationSerializer(data=kwargs)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PrincipalRegistrationConfirmationAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PrincipalRegistrationConfirmSerializer
    token_type = 'principal_registration'

    def post(self, request, *args, **kwargs):
        kwargs = super(PrincipalRegistrationConfirmationAPIView, self).get_serializer_context()
        data = request.data
        serializer = PrincipalRegistrationConfirmSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(
                detail=dict(serializer.errors.items()))


class EmailChangeRequestAPIView(SecureAPIViewBaseView):
    serializer_class = EmailChangeRequestSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        kwargs = super(EmailChangeRequestAPIView, self).get_serializer_context()
        data = request.data
        serializer = EmailChangeRequestSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(
                detail=dict(serializer.errors.items()))


class EmailChangeConfirmEditAPIView(SecureAPIViewBaseView):
    #  TODO email changed validate via session, or maybe need to pass username?
    token_type = 'email_change'

    serializer_class = EmailChangeConfirmSerializer

    def PUT(self, request, *args, **kwargs):
        kwargs = super(EmailChangeConfirmEditAPIView, self).get_serializer_context()
        data = request.data
        serializer = EmailChangeConfirmSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=dict(serializer.errors.items()))


# Google Authentication
class GoogleAuthenticationActivateView(SecureAPIViewBaseView):
    serializer_class = GoogleAuthenticatorActivateSerializer

    def get(self, request, *args, **kwargs):
        print(request.principal)
        print(request.principal._evidences_effective)
        return Response({"text": "Google Authentication"})

    def post(self, request, *args, **kwargs):
        kwargs = super(GoogleAuthenticationActivateView, self).get_serializer_context()
        serializer = GoogleAuthenticatorActivateSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response({"secret-code": serializer.salt})
        else:
            return Response({"errors": serializer.errors.items()})


class GoogleAuthenticatorVerifyView(SecureAPIViewBaseView):
    serializer_class = GoogleAuthenticatorVerifySerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "verify get"})

    def post(self, request, *args, **kwargs):
        kwargs = super(GoogleAuthenticatorVerifyView, self).get_serializer_context()
        serializer = GoogleAuthenticatorVerifySerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text": "Your code is correct"})
        return Response({"text": "verify post"})


class GoogleAuthenticatorDeleteView(SecureAPIViewBaseView):
    serializer_class = GoogleAuthenticatorDeleteSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "Delete Credential"})

    def post(self, request, *args, **kwargs):
        kwargs = super(GoogleAuthenticatorDeleteView, self).get_serializer_context()
        serializer = GoogleAuthenticatorDeleteSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.delete()
            return Response({"text": "Your credential has been deleted"})
        return Response({"text": "Delete credential post"})


class PrincipalSecurityLevelView(SecureAPIViewBaseView):

    def get(self, request, *args, **kwargs):
        if request.principal.profile.is_secure:
            content = {
                'code': '200',
                'secure': 'True',
                'text': 'Your account is secured using OTP token'
            }
        else:
            content = {
                'code': '200',
                'secure': 'False',
                'text': 'Your account is not secure'
            }
        return Response(content)
