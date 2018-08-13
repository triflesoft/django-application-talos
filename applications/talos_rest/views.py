from .exceptions.custom_exceptions import APIValidationError
from .utils import SuccessResponse, ErrorResponse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from talos.models import BasicCredentialDirectory
from talos.models import BasicIdentityDirectory
from talos_rest import permissions
from talos_rest.permissions import IsAuthenticated
from talos_rest.permissions import IsBasicAuthenticated
from talos_rest.permissions import IsSecureLevelOn


from .serializers import SessionSerializer, \
    GoogleAuthenticatorActivateRequestSerializer, \
    GoogleAuthenticatorDeleteSerializer, \
 \
    PasswordResetRequestSerializer, \
    GoogleAuthenticatorDeleteRequestSerializer, GoogleAuthenticatorActivateConfirmSerializer, \
    EmailResetRequestSerializer, \
    EmailResetValidationTokenCheckerSerializer, \
 \
    EmailChangeRequestSerializer, EmailChangeValidationTokenCheckerSerializer, \
 \
    PhoneChangeRequestSerializer, \
    PhoneChangeValidationTokenCheckerSerializer, \
    PhoneResetRequestSerializer, \
    PhoneResetValidationTokenCheckerSerializer, \
 \
    PasswordResetValidationTokenSerializer, PasswordChangeBaseSerialize, \
    PhoneResetBaseSerialize, PhoneChangeBaseSerialize, EmailResetBaseSerializer, EmailChangeBaseSerialize, \
    PasswordResetBaseSerializer, SendOTPSerializer, \
    RegistrationRequestSerializer, RegistrationMessageSerializer, \
    RegistrationConfirmationSerializer, EmailActivationRequestSerializer, EmailActivationConfirmationSerializer



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

    def get(self, request):
        if self.request.user.is_anonymous:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        else:
            credential_directory = self.request.user.credentials.otp[0].directory
            evidences = list(dict(self.request.principal._evidences_effective).keys())
            data = {
                'status': status.HTTP_200_OK,
                'result': {
                    'session_id': request.session._session.uuid,
                    'email': self.request.user.email,
                    'full_name': self.request.user.full_name,
                    'phone': self.request.user.phone,
                    'provided_evidences': evidences,
                    'otp_credential_directory': credential_directory.code
                }
            }

            return Response(data=data, status=status.HTTP_200_OK)

    def post(self, request):
        kwargs = super(SessionAPIView, self).get_serializer_context()
        data = request.data
        serializer = SessionSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            data = {
                'status': status.HTTP_200_OK,
                'result': {
                    'email': serializer.principal.email,
                    'full_name': serializer.principal.full_name,
                    'phone': serializer.principal.phone
                }
            }
            return Response(data, status=status.HTTP_200_OK)
        else:
            raise APIValidationError(detail=serializer.errors)

    def patch(self, request):
        kwargs = super(SessionAPIView, self).get_serializer_context()
        serializer = SessionSerializer(data=request.data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            data = {
                'status' : status.HTTP_200_OK,
                'result' : {}
            }
            return Response(data, status=status.HTTP_200_OK)
        else:
            raise APIValidationError(detail=serializer.errors)

    def delete(self, request):
        self.request.session.flush()
        res = {
            'status' : 200,
            'errors' : {},
            'result' : {}
        }
        return Response(res)

# Google Authentication
class GoogleAuthenticationActivateRequestView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GoogleAuthenticatorActivateRequestSerializer
    identity_directory_code = 'basic_internal'

    def post(self, request):
        kwargs = super(GoogleAuthenticationActivateRequestView, self).get_serializer_context()
        serializer = GoogleAuthenticatorActivateRequestSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse()
            success_response.set_result_pairs('secret', serializer.secret)
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class GoogleAuthenticatorActivateConfirmView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GoogleAuthenticatorActivateConfirmSerializer

    def post(self, request):
        kwargs = super(GoogleAuthenticatorActivateConfirmView, self).get_serializer_context()
        serializer = GoogleAuthenticatorActivateConfirmSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse(status.HTTP_201_CREATED)
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class GoogleAuthenticatorDeleteRequestView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated, IsSecureLevelOn,)
    serializer_class = GoogleAuthenticatorDeleteRequestSerializer

    def post(self, request):
        kwargs = super(GoogleAuthenticatorDeleteRequestView, self).get_serializer_context()
        serializer = GoogleAuthenticatorDeleteRequestSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class GoogleAuthenticatorDeleteView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated, IsSecureLevelOn,)
    serializer_class = GoogleAuthenticatorDeleteSerializer
    identity_directory_code = 'basic_internal'

    def post(self, request):
        kwargs = super(GoogleAuthenticatorDeleteView, self).get_serializer_context()
        serializer = GoogleAuthenticatorDeleteSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.delete()
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class SendOTPView(SecureAPIViewBaseView):
    serializer_class = SendOTPSerializer

    def post(self, request):
        kwargs = super(SendOTPView, self).get_serializer_context()
        serializer = SendOTPSerializer(data=request.data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            response = {
                'status': status.HTTP_200_OK,
                'result': {}
            }
            return Response(response)
        else:
            error_response = {
                'status' : status.HTTP_400_BAD_REQUEST,
                'result' : {},
                'error' : dict(serializer.errors)
            }
            return Response(error_response, status.HTTP_400_BAD_REQUEST)


class EmailChangeRequestAPIView(SecureAPIViewBaseView):
    serializer_class = EmailChangeRequestSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        kwargs = super(EmailChangeRequestAPIView, self).get_serializer_context()
        data = request.data
        serializer = EmailChangeRequestSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(
                detail=dict(serializer.errors.items()))


class EmailChangeValidationTokenCheckerAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    identity_directory_code = 'basic_internal'
    serializer_class = EmailChangeValidationTokenCheckerSerializer

    def get(self, request, **kwargs):
        context = super(EmailChangeValidationTokenCheckerAPIView, self).get_serializer_context()
        serializer = EmailChangeValidationTokenCheckerSerializer(data=kwargs, context=context)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class EmailChangeSecureAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeBaseSerialize

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(EmailChangeSecureAPIView, self).get_serializer_context()

        serializer = EmailChangeBaseSerialize(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PasswordResetRequestView(SecureAPIViewBaseView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        kwargs = super(PasswordResetRequestView, self).get_serializer_context()
        serializer = PasswordResetRequestSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            response = {
                'status' : 200,
                'result' : {
                    'secret' : serializer.token.secret
                }
            }
            return Response(response, status=status.HTTP_200_OK)
        else:
            raise APIValidationError(serializer.errors)


class PasswordResetTokenCheckerAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PasswordResetValidationTokenSerializer

    def post(self, request):
        kwargs = super(PasswordResetTokenCheckerAPIView, self).get_serializer_context()
        serializer = PasswordResetValidationTokenSerializer(data=request.data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            response = {
                'status' : status.HTTP_200_OK,
                'result' : {
                    'otp-code' : serializer.otp_code,
                    'secret' : serializer.token.secret
                }
            }
            return Response(response, status=status.HTTP_200_OK)
        else:
            raise APIValidationError(detail=serializer.errors)

class PasswordResetView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PasswordResetBaseSerializer

    def put(self, request):
        kwargs = super(PasswordResetView, self).get_serializer_context()

        serializer = PasswordResetBaseSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class EmailResetRequestAPIView(SecureAPIViewBaseView):
    serializer_class = EmailResetRequestSerializer

    def post(self, request):
        kwargs = super(EmailResetRequestAPIView, self).get_serializer_context()
        data = request.data
        serializer = EmailResetRequestSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class EmailResetValidationTokenCheckerAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = EmailResetValidationTokenCheckerSerializer

    def get(self, **kwargs):
        context = super(EmailResetValidationTokenCheckerAPIView, self).get_serializer_context()
        serializer = EmailResetValidationTokenCheckerSerializer(data=kwargs, context=context)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)

class EmailResetAPIView(SecureAPIViewBaseView):
    serializer_class = EmailResetBaseSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(EmailResetAPIView, self).get_serializer_context()

        serializer = EmailResetBaseSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneChangeRequestAPIView(SecureAPIViewBaseView):
    serializer_class = PhoneChangeRequestSerializer

    def post(self, request):
        kwargs = super(PhoneChangeRequestAPIView, self).get_serializer_context()
        data = request.data
        serializer = PhoneChangeRequestSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneChangeValidationTokenCheckerAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    identity_directory_code = 'basic_internal'
    serializer_class = PhoneChangeValidationTokenCheckerSerializer

    def get(self, request, **kwargs):
        context = super(PhoneChangeValidationTokenCheckerAPIView, self).get_serializer_context()
        serializer = PhoneChangeValidationTokenCheckerSerializer(data=kwargs, context=context)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneChangeSecureAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PhoneChangeBaseSerialize

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(PhoneChangeSecureAPIView, self).get_serializer_context()

        serializer = PhoneChangeBaseSerialize(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneResetRequestAPIView(SecureAPIViewBaseView):
    serializer_class = PhoneResetRequestSerializer

    def post(self, request):
        kwargs = super(PhoneResetRequestAPIView, self).get_serializer_context()
        data = request.data
        serializer = PhoneResetRequestSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneResetValidationTokenCheckerAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PhoneResetValidationTokenCheckerSerializer

    def get(self, **kwargs):

        serializer = PhoneResetValidationTokenCheckerSerializer(data=kwargs)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneResetAPIView(SecureAPIViewBaseView):
    serializer_class = PhoneResetBaseSerialize

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(PhoneResetAPIView, self).get_serializer_context()

        serializer = PhoneResetBaseSerialize(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PasswordChangeView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordChangeBaseSerialize
    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(PasswordChangeView, self).get_serializer_context()

        serializer = PasswordChangeBaseSerialize(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            if serializer.save():
                success_response = SuccessResponse()
                return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


# # # Registration # # #
class RegistrationRequestView(SecureAPIViewBaseView):
    serializer_class = RegistrationRequestSerializer

    def post(self, request):
        context = super(RegistrationRequestView, self).get_serializer_context()
        serializer = RegistrationRequestSerializer(data=request.data, context=context)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            response = {
                'status': status.HTTP_200_OK,
                'result': {
                    'token': serializer.uuid
                }
            }
            return Response(response, status=status.HTTP_200_OK)
        else:
            raise APIValidationError(serializer.errors)

    def patch(self, request, id):
        context = super(RegistrationRequestView, self).get_serializer_context()

        data = request.data
        data['token'] = id
        serializer = RegistrationConfirmationSerializer(data=data, context=context)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            response = {
                'status': status.HTTP_200_OK,
                'result': {}
            }

            return Response(response, status=status.HTTP_200_OK)
        else:
            raise APIValidationError(serializer.errors)



class RegistrationMessageView(SecureAPIViewBaseView):
    serializer_class = RegistrationMessageSerializer

    def post(self, request, id):
        context = super(RegistrationMessageView, self).get_serializer_context()
        data = request.data
        data['token'] = id
        serializer = RegistrationMessageSerializer(data=data, context=context)

        if serializer.is_valid(raise_exception=False):
            serializer.send()
            response = {
                'status' : status.HTTP_200_OK,
                'result' : {
                    'token' : serializer.token
                }
            }
            return Response(response, status=status.HTTP_200_OK)
        else:
            raise APIValidationError(serializer.errors)

class EmailActivationRequestView(SecureAPIViewBaseView):
    serializer_class = EmailActivationRequestSerializer

    def post(self, request):
        context = super(EmailActivationRequestView, self).get_serializer_context()
        serializer = EmailActivationRequestSerializer(data=request.data, context=context)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            data = {
                'status' : status.HTTP_200_OK,
                'result' : {}
            }
            return Response(data, status=status.HTTP_200_OK)
        else:
            raise APIValidationError(serializer.errors)


class EmailActivationConfirmationView(SecureAPIViewBaseView):
    serializer_class = EmailActivationConfirmationSerializer

    def post(self, request, secret):
        context = super(EmailActivationConfirmationView, self).get_serializer_context()
        data = request.data
        data['secret'] = secret

        serializer = EmailActivationConfirmationSerializer(data=data, context=context)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            data = {
                'status' : status.HTTP_200_OK,
                'result' : {}
            }
            return Response(data, status=status.HTTP_200_OK)
        else:
            raise APIValidationError(serializer.errors)
