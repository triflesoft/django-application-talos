from django.utils.decorators import method_decorator

from django.views.decorators.cache import never_cache

from django.views.decorators.debug import sensitive_post_parameters

from rest_framework.response import Response

from talos_rest import permissions
from .utils import SuccessResponse, ErrorResponse
from rest_framework.generics import GenericAPIView
from rest_framework import status
# Serializer classes
from .exceptions.custom_exceptions import APIValidationError
from .serializers import SessionSerializer, \
    GoogleAuthenticatorActivateRequestSerializer, \
    GoogleAuthenticatorDeleteSerializer, GeneratePhoneCodeForAuthorizedUserSerializer, \
    VerifyPhoneCodeForAuthorizedUserSerializer, ChangePasswordInsecureSerializer, \
    ChangePasswordSecureSerializer, AddSMSEvidenceSerializer, \
    AddGoogleEvidenceSerializer, GeneratePhoneCodeForUnAuthorizedUserSerializer, \
    BasicRegistrationSerializer, PasswordResetRequestSerializer, \
    GoogleAuthenticatorDeleteRequestSerializer, GoogleAuthenticatorActivateConfirmSerializer, \
    VerifyPhoneCodeForUnAuthorizedUserSerializer, EmailResetRequestSerializer, \
    EmailResetValidationTokenCheckerSerializer, GoogleAuthenticatorChangeRequestSerializer, \
    GoogleAuthenticatorChangeConfirmSerializer, GoogleAuthenticatorChangeDoneSerializer, \
    EmailChangeRequestSerializer, EmailChangeValidationTokenCheckerSerializer, \
    EmailChangeInsecureSerializer, EmailChangeSecureSerializer, EmailResetInsecureSerializer, \
    EmailResetSecureSerializer, PhoneChangeRequestSerializer, \
    PhoneChangeValidationTokenCheckerSerializer, PhoneChangeSecureSerializer, \
    PhoneChangeInsecureSerializer, PhoneResetRequestSerializer, \
    PhoneResetValidationTokenCheckerSerializer, PhoneResetInsecureSerializer, \
    PhoneResetSecureSerializer, PasswordChangeInsecureSerializer, PasswordChangeSecureSerializer, \
    LdapLoginSerializer, PasswordResetInsecureSerializer, PasswordResetSecureSerializer

from talos_rest.permissions import IsAuthenticated, IsBasicAuthenticated, IsSecureLevelOn


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

        if str(self.request.user) == 'Anonymous':

            response = ErrorResponse(status=status.HTTP_404_NOT_FOUND)
        else:
            response = SuccessResponse()
            response.set_result_pairs('session_id', request.session._session.uuid)

        return Response(data=response.data,
                        status=response.status)

    def post(self, request):

        kwargs = super(SessionAPIView, self).get_serializer_context()
        data = request.data
        serializer = SessionSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)

    def delete(self, request):
        if str(self.request.user) == 'Anonymous':
            reseponse = ErrorResponse(status=status.HTTP_404_NOT_FOUND)
        else:
            self.request.session.flush()
            reseponse = SuccessResponse()
        return Response(data=reseponse.data,
                        status=reseponse.status)


class LdapSessionAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'ldap'

    serializer_class = LdapLoginSerializer

    def get(self, request):

        if str(self.request.user) == 'Anonymous':

            response = ErrorResponse(status=status.HTTP_404_NOT_FOUND)
        else:
            response = SuccessResponse()
            response.set_result_pairs('session_id', request.session._session.uuid)

        return Response(data=response.data,
                        status=response.status)

    def post(self, request):

        kwargs = super(LdapSessionAPIView, self).get_serializer_context()
        data = request.data
        serializer = LdapLoginSerializer(data=data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)

    def delete(self, request):

        if str(self.request.user) == 'Anonymous':
            reseponse = ErrorResponse(status=status.HTTP_404_NOT_FOUND)
        else:
            self.request.session.flush()
            reseponse = SuccessResponse()
        return Response(data=reseponse.data,
                        status=reseponse.status)


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


class GoogleAuthenticatorChangeRequestView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GoogleAuthenticatorChangeRequestSerializer

    def post(self, request):
        kwargs = super(GoogleAuthenticatorChangeRequestView, self).get_serializer_context()
        serializer = GoogleAuthenticatorChangeRequestSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class GoogleAuthenticatorChangeConfirmView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GoogleAuthenticatorChangeConfirmSerializer
    identity_directory_code = 'basic_internal'

    def post(self, request):
        kwargs = super(GoogleAuthenticatorChangeConfirmView, self).get_serializer_context()
        serializer = GoogleAuthenticatorChangeConfirmSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse()
            success_response.set_result_pairs('secret', serializer.salt)
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class GoogleAuthenticatorChangeDoneView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GoogleAuthenticatorChangeDoneSerializer

    def post(self, request):
        kwargs = super(GoogleAuthenticatorChangeDoneView, self).get_serializer_context()
        serializer = GoogleAuthenticatorChangeDoneSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class PrincipalSecurityLevelView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        from talos.models import OneTimePasswordCredential
        from talos.models import OneTimePasswordCredentialDirectory

        directory = OneTimePasswordCredentialDirectory.objects.get(
            code='onetimepassword_internal_google_authenticator')
        success_response = SuccessResponse()
        try:

            OneTimePasswordCredential(principal=self.principal, directory=directory)
            success_response.set_result_pairs('secure', 'True')
        except OneTimePasswordCredential.DoesNotExist:
            success_response.set_result_pairs('secure', 'False')
        return Response(data=success_response.data)


class PrincipalSecurityLevelByTokenView(SecureAPIViewBaseView):

    def get(self, **kwargs):
        from talos.models import ValidationToken
        #from talos.models import PrincipalProfile
        from talos.models import OneTimePasswordCredential
        from talos.models import OneTimePasswordCredentialDirectory

        success_response = SuccessResponse()
        try:
            validation_token = ValidationToken.objects.get(secret=kwargs.get('secret'))
            directory = OneTimePasswordCredentialDirectory.objects.get(
                code='onetimepassword_internal_google_authenticator')

            try:
                OneTimePasswordCredential(principal=self.principal, directory=directory)
                success_response.set_result_pairs('secure', 'True')
            except OneTimePasswordCredential.DoesNotExist:
                success_response.set_result_pairs('secure', 'False')
        except ValidationToken.DoesNotExist:
            error_response = ErrorResponse()
            return Response(data=error_response.data)
        return Response(data=success_response.data)


class GeneratePhoneCodeForAuthorizedUserView(SecureAPIViewBaseView):
    permission_classes = (IsBasicAuthenticated,)
    serializer_class = GeneratePhoneCodeForAuthorizedUserSerializer

    def post(self, request):
        kwargs = super(GeneratePhoneCodeForAuthorizedUserView, self).get_serializer_context()
        serializer = GeneratePhoneCodeForAuthorizedUserSerializer(data=request.data, context=kwargs)
        if serializer.is_valid():
            serializer.save()
        success_response = SuccessResponse()
        return Response(success_response.data)


class VerifyPhoneCodeForAuthorizedUserView(SecureAPIViewBaseView):
    permission_classes = (IsBasicAuthenticated,)
    serializer_class = VerifyPhoneCodeForAuthorizedUserSerializer

    def post(self, request):
        kwargs = super(VerifyPhoneCodeForAuthorizedUserView, self).get_serializer_context()
        serializer = VerifyPhoneCodeForAuthorizedUserSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            success_response = SuccessResponse()
            success_response.set_result_pairs('text', 'your code is correct')
            return Response(success_response.data)


class ChangePasswordInsecureView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordInsecureSerializer

    identity_directory_code = 'basic_internal'

    def post(self, request):
        kwargs = super(ChangePasswordInsecureView, self).get_serializer_context()
        serializer = ChangePasswordInsecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class ChangePasswordSecureView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSecureSerializer

    identity_directory_code = 'basic_internal'

    def post(self, request):
        kwargs = super(ChangePasswordSecureView, self).get_serializer_context()
        serializer = ChangePasswordSecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class AddSMSEvidenceView(SecureAPIViewBaseView):
    permission_classes = (IsBasicAuthenticated,)
    serializer_class = AddSMSEvidenceSerializer

    def post(self, request):
        kwargs = super(AddSMSEvidenceView, self).get_serializer_context()
        serializer = AddSMSEvidenceSerializer(data=request.data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class AddGoogleEvidenceView(SecureAPIViewBaseView):
    permission_classes = (IsBasicAuthenticated,)
    serializer_class = AddGoogleEvidenceSerializer

    def post(self, request):
        kwargs = super(AddGoogleEvidenceView, self).get_serializer_context()
        serializer = AddGoogleEvidenceSerializer(data=request.data,
                                                 context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class GeneratePhoneCodeForUnAuthorizedUserView(SecureAPIViewBaseView):
    serializer_class = GeneratePhoneCodeForUnAuthorizedUserSerializer

    def post(self, request, *args, **kwargs):
        kwargs = super(GeneratePhoneCodeForUnAuthorizedUserView, self).__init__(*args, **kwargs)
        serializer = GeneratePhoneCodeForUnAuthorizedUserSerializer(data=request.data,
                                                                    context=kwargs)

        if serializer.is_valid(raise_exception=False):
            from rest_framework.serializers import ValidationError
            from talos_rest import constants
            try:
                serializer.save()
            except ValidationError:
                error_response = ErrorResponse()
                error_response.set_error_pairs('phone', constants.PHONE_INVALID_CODE)
                error_response.set_details_pairs('phone', 'Error while sending sms')
                return Response(error_response.data, error_response.status)

            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class VerifyPhoneCodeForUnAuthorizedUserView(SecureAPIViewBaseView):
    serializer_class = VerifyPhoneCodeForUnAuthorizedUserSerializer

    def post(self, request):
        kwargs = super(VerifyPhoneCodeForUnAuthorizedUserView, self).get_serializer_context()
        serializer = VerifyPhoneCodeForUnAuthorizedUserSerializer(data=request.data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            success_response = SuccessResponse()
            success_response.set_result_pairs('token', serializer.token)
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class BasicRegistrationView(SecureAPIViewBaseView):
    serializer_class = BasicRegistrationSerializer
    identity_directory_code = 'basic_internal'

    def post(self, request):
        kwargs = super(BasicRegistrationView, self).get_serializer_context()
        serializer = BasicRegistrationSerializer(data=request.data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse(status=status.HTTP_201_CREATED)
            return Response(success_response.data, status=success_response.status)
        else:
            raise APIValidationError(serializer.errors)


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

        serializer = EmailChangeValidationTokenCheckerSerializer(data=kwargs, context=request)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class EmailChangeInsecureAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeInsecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(EmailChangeInsecureAPIView, self).get_serializer_context()
        serializer = EmailChangeInsecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class EmailChangeSecureAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated, IsSecureLevelOn,)
    serializer_class = EmailChangeSecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(EmailChangeSecureAPIView, self).get_serializer_context()
        serializer = EmailChangeSecureSerializer(data=request.data, context=kwargs)
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
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class PasswordResetInsecureView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PasswordResetInsecureSerializer

    def put(self, request):
        kwargs = super(PasswordResetInsecureView, self).get_serializer_context()
        serializer = PasswordResetInsecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class PasswordResetSecureView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PasswordResetSecureSerializer

    def put(self, request):
        kwargs = super(PasswordResetSecureView, self).get_serializer_context()
        serializer = PasswordResetSecureSerializer(data=request.data, context=kwargs)
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

        serializer = EmailResetValidationTokenCheckerSerializer(data=kwargs)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


#
class EmailResetInsecureAPIView(SecureAPIViewBaseView):
    serializer_class = EmailResetInsecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(EmailResetInsecureAPIView, self).get_serializer_context()
        serializer = EmailResetInsecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class EmailResetSecureAPIView(SecureAPIViewBaseView):
    serializer_class = EmailResetSecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(EmailResetSecureAPIView, self).get_serializer_context()
        serializer = EmailResetSecureSerializer(data=request.data, context=kwargs)
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

        serializer = PhoneChangeValidationTokenCheckerSerializer(data=kwargs, context=request)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneChangeSecureAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PhoneChangeSecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(PhoneChangeSecureAPIView, self).get_serializer_context()
        serializer = PhoneChangeSecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneChangeInsecureAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PhoneChangeInsecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(PhoneChangeInsecureAPIView, self).get_serializer_context()
        serializer = PhoneChangeInsecureSerializer(data=request.data, context=kwargs)
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


class PhoneResetInsecureAPIView(SecureAPIViewBaseView):
    serializer_class = PhoneResetInsecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(PhoneResetInsecureAPIView, self).get_serializer_context()
        serializer = PhoneResetInsecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneResetSecureAPIView(SecureAPIViewBaseView):
    serializer_class = PhoneResetSecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(PhoneResetSecureAPIView, self).get_serializer_context()
        serializer = PhoneResetSecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class ProvidedEvidencesView(SecureAPIViewBaseView):

    def get(self, request):
        evidences = list(dict(self.request.principal._evidences_effective).keys())
        success_response = SuccessResponse()
        success_response.set_result_pairs('provided-evidences', evidences)
        return Response(success_response.data)


class TestView(SecureAPIViewBaseView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self):
        return Response({"text": "Test"})


class PasswordChangeInsecureView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordChangeInsecureSerializer
    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(PasswordChangeInsecureView, self).get_serializer_context()
        serializer = PasswordChangeInsecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            if serializer.save():
                success_response = SuccessResponse()
                return Response(success_response.data, success_response.status)
            else:
                error_response = ErrorResponse()
                return Response(error_response.data, error_response.status)
        else:
            raise APIValidationError(detail=serializer.errors)


class PasswordChangeSecureView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordChangeSecureSerializer
    identity_directory_code = 'basic_internal'

    def put(self, request):
        kwargs = super(PasswordChangeSecureView, self).get_serializer_context()
        serializer = PasswordChangeSecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            if serializer.save():
                success_response = SuccessResponse()
                return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)
