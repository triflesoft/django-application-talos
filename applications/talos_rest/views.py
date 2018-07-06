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
    VerifyPhoneCodeForAuthorizedUserSerializer, \
 \
    GeneratePhoneCodeForUnAuthorizedUserSerializer, \
    BasicRegistrationSerializer, PasswordResetRequestSerializer, \
    GoogleAuthenticatorDeleteRequestSerializer, GoogleAuthenticatorActivateConfirmSerializer, \
    EmailResetRequestSerializer, \
    EmailResetValidationTokenCheckerSerializer,  \
    \
    EmailChangeRequestSerializer, EmailChangeValidationTokenCheckerSerializer, \
 \
    PhoneChangeRequestSerializer, \
    PhoneChangeValidationTokenCheckerSerializer, \
    PhoneResetRequestSerializer, \
    PhoneResetValidationTokenCheckerSerializer, \
 \
    LdapLoginSerializer, \
    PasswordResetValidationTokenSerializer, PasswordChangeBaseSerialize, AddEvidenceBaseSerialize, \
    PhoneResetBaseSerialize, PhoneChangeBaseSerialize, EmailResetBaseSerializer, EmailChangeBaseSerialize, \
    PasswordResetBaseSerializer

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


class AddEvidenceView(SecureAPIViewBaseView):
    permission_classes = (IsBasicAuthenticated,)
    serializer_class = AddEvidenceBaseSerialize

    def post(self, request, directory_code, error_code):
        kwargs = super(AddEvidenceView, self).get_serializer_context()

        kwargs['directory_code'] = directory_code
        kwargs['error_code'] = error_code

        serializer = AddEvidenceBaseSerialize(data=request.data,
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
        kwargs = super(GeneratePhoneCodeForUnAuthorizedUserView, self).get_serializer_context(*args, **kwargs)

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


# class VerifyPhoneCodeForUnAuthorizedUserView(SecureAPIViewBaseView):
#     serializer_class = VerifyPhoneCodeForUnAuthorizedUserSerializer
#
#     def post(self, request):
#         kwargs = super(VerifyPhoneCodeForUnAuthorizedUserView, self).get_serializer_context()
#         serializer = VerifyPhoneCodeForUnAuthorizedUserSerializer(data=request.data, context=kwargs)
#
#         if serializer.is_valid(raise_exception=False):
#             success_response = SuccessResponse()
#             success_response.set_result_pairs('token', serializer.token)
#             return Response(success_response.data, success_response.status)
#         else:
#             raise APIValidationError(serializer.errors)


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


class EmailChangeSecureAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeBaseSerialize

    identity_directory_code = 'basic_internal'

    def put(self, request, directory_code, error_code):
        kwargs = super(EmailChangeSecureAPIView, self).get_serializer_context()

        kwargs['directory_code'] = directory_code
        kwargs['error_code'] = error_code

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
            success_response = SuccessResponse()
            return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)


class PasswordResetTokenCheckerAPIView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PasswordResetValidationTokenSerializer

    def get(self, **kwargs):

        serializer = PasswordResetValidationTokenSerializer(data=kwargs)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)

class PasswordResetView(SecureAPIViewBaseView):
    identity_directory_code = 'basic_internal'
    serializer_class = PasswordResetBaseSerializer

    def put(self, request, directory_code, error_code):
        kwargs = super(PasswordResetView, self).get_serializer_context()

        kwargs['directory_code'] = directory_code
        kwargs['error_code'] = error_code

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

        serializer = EmailResetValidationTokenCheckerSerializer(data=kwargs)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)

class EmailResetAPIView(SecureAPIViewBaseView):
    serializer_class = EmailResetBaseSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request, directory_code, error_code):
        kwargs = super(EmailResetAPIView, self).get_serializer_context()

        kwargs['directory_code'] = directory_code
        kwargs['error_code'] = error_code

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

        serializer = PhoneChangeValidationTokenCheckerSerializer(data=kwargs, context=request)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneChangeSecureAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PhoneChangeBaseSerialize

    identity_directory_code = 'basic_internal'

    def put(self, request, directory_code, error_code):
        kwargs = super(PhoneChangeSecureAPIView, self).get_serializer_context()

        kwargs['directory_code'] = directory_code
        kwargs['error_code'] = error_code

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

    def put(self, request, directory_code, error_code):
        kwargs = super(PhoneResetAPIView, self).get_serializer_context()

        kwargs['directory_code'] = directory_code
        kwargs['error_code'] = error_code

        serializer = PhoneResetBaseSerialize(data=request.data, context=kwargs)
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



class PasswordChangeView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordChangeBaseSerialize
    identity_directory_code = 'basic_internal'

    def put(self, request, directory_code, error_code):
        kwargs = super(PasswordChangeView, self).get_serializer_context()

        kwargs['directory_code'] = directory_code
        kwargs['error_code'] = error_code

        serializer = PasswordChangeBaseSerialize(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            if serializer.save():
                success_response = SuccessResponse()
                return Response(success_response.data, success_response.status)
        else:
            raise APIValidationError(serializer.errors)
