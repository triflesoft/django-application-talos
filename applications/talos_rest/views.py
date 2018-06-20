from django.utils.decorators import method_decorator

from django.views.decorators.cache import never_cache

from django.views.decorators.debug import sensitive_post_parameters

from rest_framework.response import Response

from rest_framework.generics import GenericAPIView

# Serializer classes
from .exceptions.custom_exceptions import APIValidationError
from talos_test_app.serializers import (BasicLoginSerializer,
                                        PrincipalRegistrationRequestSerializer,
                                        PrincipalRegistrationConfirmSerializer,
                                        PrincipalRegistrationTokenValidationSerializer,
                                        EmailChangeRequestSerializer,
                                        EmailChangeConfirmSerializer)

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
                # TODO For what is this?
                # kwargs['initial'].update({'new_email': token.email})
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


class BasicLoginAPIView(SecureAPIViewBaseView):
    """
    get:
    Return a list of all the existing users.

    {"user": str(request.principal)}

    post:
    Create a new user instance.

    {"Success": session_id,
     "principal": principal }
    """
    identity_directory_code = 'basic_internal'

    serializer_class = BasicLoginSerializer

    def get(self, request, *args, **kwargs):
        return Response({"user": str(request.principal)})

    def post(self, request, *args, **kwargs):
        kwargs = super(BasicLoginAPIView, self).get_serializer_context()
        data = request.data
        serializer = BasicLoginSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            session_id = self.request.session._session.uuid
            principal = str(self.request._request.user)
            # return Response(
            #     { "code" : 200,
            #              "result":{
            #              "user" : principal,
            #              'session_id' : session_id}}         )
            return Response(serializer.data)
        else:
            raise APIValidationError(
                                     detail=dict(serializer.errors.items()))


class PrincipalRegistrationRequestEditAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PrincipalRegistrationRequestSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "user registration request"})

    def post(self, request, *args, **kwargs):
        kwargs = super(PrincipalRegistrationRequestEditAPIView, self).get_serializer_context()
        data = request.data
        serializer = PrincipalRegistrationRequestSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text": "registration url has been sent on your email"})
        else:
            return Response({"error": dict(serializer.errors.items())})


class PrincipalRegistrationTokenValidationAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PrincipalRegistrationTokenValidationSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "token validation"})

    def post(self, request, *args, **kwargs):
        kwargs = super(PrincipalRegistrationTokenValidationAPIView, self).get_serializer_context()
        data = request.data
        serializer = PrincipalRegistrationTokenValidationSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            return Response({"token": data['token']})
        else:
            raise APIValidationError(
                                     detail=dict(serializer.errors.items()))



class PrincipalRegistrationConfirmationAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PrincipalRegistrationConfirmSerializer
    token_type = 'principal_registration'

    def get(self, request, *args, **kwargs):
        return Response({"text": "user registration confirmation"})

    def post(self, request, *args, **kwargs):
        kwargs = super(PrincipalRegistrationConfirmationAPIView, self).get_serializer_context()
        data = request.data
        serializer = PrincipalRegistrationConfirmSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response({"text": "user registered successufly "})
        else:
            raise APIValidationError(
                                     detail=dict(serializer.errors.items()))



class LogoutAPIView(SecureTemplateViewBaseView):
    def get_context_data(self, **kwargs):
        # TODO What what we need this part?
        # context = super(LogoutAPIView, self).get_context_data(**kwargs)
        pass
        # old_principal = self.request.principal

        # context['old_principal'] = old_principal

    def get(self, request, *args, **kwargs):
        self.request.session.flush()

        return Response({"text": "user logged out"})


class EmailChangeRequestEditAPIView(SecureAPIViewBaseView):
    serializer_class = EmailChangeRequestSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "Email change request"})

    def post(self, request, *args, **kwargs):
        kwargs = super(EmailChangeRequestEditAPIView, self).get_serializer_context()
        data = request.data
        serializer = EmailChangeRequestSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response({"text": "email change request send to mail"})
        else:
            raise APIValidationError(
                                     detail=dict(serializer.errors.items()))


class EmailChangeConfirmEditAPIView(SecureAPIViewBaseView):
    #  TODO email changed validate via session, or maybe need to pass username?
    token_type = 'email_change'

    serializer_class = EmailChangeConfirmSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "Email change confirmation"})

    def post(self, request, *args, **kwargs):
        kwargs = super(EmailChangeConfirmEditAPIView, self).get_serializer_context()
        data = request.data
        serializer = EmailChangeConfirmSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response({"text": "email change request done"})
        else:
            raise APIValidationError(detail=dict(serializer.errors.items()))
