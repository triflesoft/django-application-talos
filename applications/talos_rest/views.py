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
from talos_rest.serializers import SessionSerializer, \
    GoogleAuthenticatorActivateRequestSerializer, GoogleAuthenticatorVerifySerializer, \
    GoogleAuthenticatorDeleteSerializer, GeneratePhoneCodeForAuthorizedUserSerializer, \
    VerifyPhoneCodeForAuthorizedUserSerializer, ChangePasswordInsecureSerializer, \
    ChangePasswordSecureSerializer, AuthorizationUsingSMSSerializer, \
    AuthorizationUsingGoogleAuthenticatorSerializer, GeneratePhoneCodeForUnAuthorizedUserSerializer, \
    BasicRegistrationSerializer, PasswordResetRequestSerializer, PasswordResetConfirmSerializer, \
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
    PhoneResetSecureSerializer, PasswordChangeInsecureSerializer


from talos_rest.permissions import IsAuthenticated


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

            response = ErrorResponse(status=status.HTTP_404_NOT_FOUND)
        else:
            response = SuccessResponse()
            response.set_result_pairs('session_id', request.session._session.uuid)

        return Response(data=response.data,
                        status=response.status)

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

    def get(self, request, *args, **kwargs):
        print("Activate Request")
        print(self.request.session.__dict__)
        return Response({"text": "Google Authentication"})

    def post(self, request, *args, **kwargs):
        kwargs = super(GoogleAuthenticationActivateRequestView, self).get_serializer_context()
        serializer = GoogleAuthenticatorActivateRequestSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response({"secret": serializer.salt})
        else:
            return Response({"errors": serializer.errors.items()})


class GoogleAuthenticatorActivateConfirmView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GoogleAuthenticatorActivateConfirmSerializer

    def get(self, request, *args, **kwargs):
        print("Activate Confirm")
        print(self.request.session.__dict__)
        return Response({"text": "Google Authenticator Confirm"})

    def post(self, request, *args, **kwargs):
        kwargs = super(GoogleAuthenticatorActivateConfirmView, self).get_serializer_context()
        serializer = GoogleAuthenticatorActivateConfirmSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text": "Google Authenticator has been added"})


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


class GoogleAuthenticatorDeleteRequestView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GoogleAuthenticatorDeleteRequestSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "Google Authenticator Delete"})

    def post(self, request, *args, **kwargs):
        kwargs = super(GoogleAuthenticatorDeleteRequestView, self).get_serializer_context()
        serializer = GoogleAuthenticatorDeleteRequestSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text": "Email has been sent"})


class GoogleAuthenticatorDeleteView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GoogleAuthenticatorDeleteSerializer
    identity_directory_code = 'basic_internal'

    def get(self, request, *args, **kwargs):
        return Response({"text": "Delete Credential"})

    def post(self, request, *args, **kwargs):
        kwargs = super(GoogleAuthenticatorDeleteView, self).get_serializer_context()
        serializer = GoogleAuthenticatorDeleteSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.delete()
            return Response({"text": "Your credential has been deleted"})
        return Response({"text": "Delete credential post"})


class GoogleAuthenticatorChangeRequestView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GoogleAuthenticatorChangeRequestSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "Google Authenticator change"})

    def post(self, request, *args, **kwargs):
        kwargs = super(GoogleAuthenticatorChangeRequestView, self).get_serializer_context()
        serializer = GoogleAuthenticatorChangeRequestSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
        return Response({"text": "Google authenticator change"})


class GoogleAuthenticatorChangeConfirmView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GoogleAuthenticatorChangeConfirmSerializer
    identity_directory_code = 'basic_internal'

    def get(self, request, *args, **kwargs):
        return Response({"text": "Google Authenticator Change Confirm"})

    def post(self, request, *args, **kwargs):
        kwargs = super(GoogleAuthenticatorChangeConfirmView, self).get_serializer_context()
        serializer = GoogleAuthenticatorChangeConfirmSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"secret": serializer.salt})
        return Response({"text": "Google Authenicaor Change confirm post"})


class GoogleAuthenticatorChangeDoneView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GoogleAuthenticatorChangeDoneSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "Google Authneticator Change Done"})

    def post(self, request, *args, **kwargs):
        kwargs = super(GoogleAuthenticatorChangeDoneView, self).get_serializer_context()
        serializer = GoogleAuthenticatorChangeDoneSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text": "Credential has been changed"})


class PrincipalSecurityLevelView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        success_response = SuccessResponse()

        if request.principal.profile.is_secure:
            success_response.set_result_pairs('secure', 'True')
        else:
            success_response.set_result_pairs('secure', 'False')
        return Response(data=success_response.data)


class PrincipalSecurityLevelByTokenView(SecureAPIViewBaseView):

    def get(self, request, *args, **kwargs):
        from talos.models import ValidationToken
        from talos.models import PrincipalProfile
        success_response = SuccessResponse()
        try:
            validation_token = ValidationToken.objects.get(secret=kwargs.get('secret'))
            profile = PrincipalProfile.objects.get(principal=validation_token.principal)
            if profile.is_secure:
                success_response.set_result_pairs('secure', 'True')
            else:
                success_response.set_result_pairs('secure', 'False')
        except ValidationToken.DoesNotExist:
            error_response = ErrorResponse()
            return Response(data=error_response.data)
        return Response(data=success_response.data)


class GeneratePhoneCodeForAuthorizedUserView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = GeneratePhoneCodeForAuthorizedUserSerializer

    def post(self, request, *args, **kwargs):
        kwargs = super(GeneratePhoneCodeForAuthorizedUserView, self).get_serializer_context()
        serializer = GeneratePhoneCodeForAuthorizedUserSerializer(data=request.data, context=kwargs)
        if serializer.is_valid():
            serializer.save()
        success_response = SuccessResponse()
        return Response(success_response.data)


class VerifyPhoneCodeForAuthorizedUserView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = VerifyPhoneCodeForAuthorizedUserSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "Verify SMS Code"})

    def post(self, request, *args, **kwargs):
        kwargs = super(VerifyPhoneCodeForAuthorizedUserView, self).get_serializer_context()
        serializer = VerifyPhoneCodeForAuthorizedUserSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            context = {
                "code": "200",
                "text": "Your code is correct"
            }
            return Response(context)
        return Response({"text": "Giorgi"})


class ChangePasswordInsecureView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordInsecureSerializer

    identity_directory_code = 'basic_internal'

    def get(self, request, *args, **kwargs):
        return Response({"text": "Change Password"})

    def post(self, request, *args, **kwargs):
        kwargs = super(ChangePasswordInsecureView, self).get_serializer_context()
        serializer = ChangePasswordInsecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text": "Your password has been changed"})
        return Response({"text": "Giorgi"})


class ChangePasswordSecureView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSecureSerializer

    identity_directory_code = 'basic_internal'

    def get(self, request, *args, **kwargs):
        return Response({"text": "Change Password Secure"})

    def post(self, request, *args, **kwargs):
        kwargs = super(ChangePasswordSecureView, self).get_serializer_context()
        serializer = ChangePasswordSecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text": "Your password has been changed succesfully"})
        return Response({"text": "Change Password Secure POST Request"})


class AuthorizationUsingSMSView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = AuthorizationUsingSMSSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "Authorization Using SMS Code"})

    def post(self, request, *args, **kwargs):
        kwargs = super(AuthorizationUsingSMSView, self).get_serializer_context()
        serializer = AuthorizationUsingSMSSerializer(data=request.data, context=kwargs)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text": "You have logged in succesfully using SMS Code"})


class AuthorizationUsingGoogleAuthenticatorView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = AuthorizationUsingGoogleAuthenticatorSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "Authorization using Google Authenticator"})

    def post(self, request, *args, **kwargs):
        kwargs = super(AuthorizationUsingGoogleAuthenticatorView, self).get_serializer_context()
        serializer = AuthorizationUsingGoogleAuthenticatorSerializer(data=request.data,
                                                                     context=kwargs)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text": "You have logged in succesfully using Google Authenticatr"})


class GeneratePhoneCodeForUnAuthorizedUserView(SecureAPIViewBaseView):
    serializer_class = GeneratePhoneCodeForUnAuthorizedUserSerializer

    def post(self, request, *args, **kwargs):
        kwargs = super(GeneratePhoneCodeForUnAuthorizedUserView, self).__init__(*args, **kwargs)
        serializer = GeneratePhoneCodeForUnAuthorizedUserSerializer(data=request.data,
                                                                    context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(serializer.errors)


class VerifyPhoneCodeForUnAuthorizedUserView(SecureAPIViewBaseView):
    serializer_class = VerifyPhoneCodeForUnAuthorizedUserSerializer

    def post(self, request, *args, **kwargs):
        kwargs = super(VerifyPhoneCodeForUnAuthorizedUserView, self).get_serializer_context()
        serializer = VerifyPhoneCodeForUnAuthorizedUserSerializer(data=request.data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            data = {'token': serializer.token}
            data.update(serializer.data)
            return Response(data)
        else:
            raise APIValidationError(serializer.errors)


class BasicRegistrationView(SecureAPIViewBaseView):
    serializer_class = BasicRegistrationSerializer
    identity_directory_code = 'basic_internal'

    def get(self, request, *args, **kwargs):
        return Response({"text": "Basic Registration"})

    def post(self, request, *args, **kwargs):
        kwargs = super(BasicRegistrationView, self).get_serializer_context()
        serializer = BasicRegistrationSerializer(data=request.data, context=kwargs)

        if serializer.is_valid(raise_exception=False):
            serializer.save()
            data = {
                'status': status.HTTP_201_CREATED,
                'result': {},
            }
            return Response(data, status=status.HTTP_201_CREATED)
        else:
            raise APIValidationError(serializer.errors)


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


class EmailChangeValidationTokenCheckerAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    identity_directory_code = 'basic_internal'
    serializer_class = EmailChangeValidationTokenCheckerSerializer

    def get(self, request, *args, **kwargs):

        serializer = EmailChangeValidationTokenCheckerSerializer(data=kwargs, context=request)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class EmailChangeInsecureAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeInsecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request, *args, **kwargs):
        kwargs = super(EmailChangeInsecureAPIView, self).get_serializer_context()
        serializer = EmailChangeInsecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class EmailChangeSecureAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailChangeSecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request, *args, **kwargs):
        kwargs = super(EmailChangeSecureAPIView, self).get_serializer_context()
        serializer = EmailChangeSecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PasswordResetRequestView(SecureAPIViewBaseView):
    serializer_class = PasswordResetRequestSerializer

    def get(self, request, *args, **kwargs):
        return Response({"text": "Password Reset View"})

    def post(self, request, *args, **kwargs):
        kwargs = super(PasswordResetRequestView, self).get_serializer_context()
        serializer = PasswordResetRequestSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text": "Email has been sent"})
        return Response({"text": "Password Reset view"})


class PasswordResetConfirmView(SecureAPIViewBaseView):
    serializer_class = PasswordResetConfirmSerializer
    identity_directory_code = 'basic_internal'

    def get(self, request, *args, **kwargs):
        return Response({"text": "PasswordResetConfirm View"})

    def post(self, request, *args, **kwargs):
        kwargs = super(PasswordResetConfirmView, self).get_serializer_context()
        serializer = PasswordResetConfirmSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"text": "Your password has been changed"})
        return Response({"text": "password reset confirm view"})


class EmailResetRequestAPIView(SecureAPIViewBaseView):
    serializer_class = EmailResetRequestSerializer

    def post(self, request, *args, **kwargs):
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

    def get(self, request, *args, **kwargs):

        serializer = EmailResetValidationTokenCheckerSerializer(data=kwargs)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


#
class EmailResetInsecureAPIView(SecureAPIViewBaseView):
    serializer_class = EmailResetInsecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request, *args, **kwargs):
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

    def put(self, request, *args, **kwargs):
        kwargs = super(EmailResetSecureAPIView, self).get_serializer_context()
        serializer = EmailResetSecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneChangeRequestAPIView(SecureAPIViewBaseView):
    serializer_class = PhoneChangeRequestSerializer

    def post(self, request, *args, **kwargs):
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

    def get(self, request, *args, **kwargs):

        serializer = PhoneChangeValidationTokenCheckerSerializer(data=kwargs, context=request)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class PhoneChangeSecureAPIView(SecureAPIViewBaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PhoneChangeSecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request, *args, **kwargs):
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

    def put(self, request, *args, **kwargs):
        kwargs = super(PhoneChangeInsecureAPIView, self).get_serializer_context()
        serializer = PhoneChangeInsecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)

class PhoneResetRequestAPIView(SecureAPIViewBaseView):
    serializer_class = PhoneResetRequestSerializer

    def post(self, request, *args, **kwargs):
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

    def get(self, request, *args, **kwargs):

        serializer = PhoneResetValidationTokenCheckerSerializer(data=kwargs)

        if serializer.is_valid(raise_exception=False):
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)

class PhoneResetInsecureAPIView(SecureAPIViewBaseView):
    serializer_class = PhoneResetInsecureSerializer

    identity_directory_code = 'basic_internal'

    def put(self, request, *args, **kwargs):
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

    def put(self, request, *args, **kwargs):
        kwargs = super(PhoneResetSecureAPIView, self).get_serializer_context()
        serializer = PhoneResetSecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            serializer.save()
            return Response(serializer.data)
        else:
            raise APIValidationError(detail=serializer.errors)


class ProvidedEvidencesView(SecureAPIViewBaseView):

    def get(self, request, *args, **kwargs):
        evidences = list(dict(self.request.principal._evidences_effective).keys())
        data = {'provided-evidences' : evidences}
        return Response(data)


class TestView(SecureAPIViewBaseView):

    permission_classes = (permissions.IsAuthenticated, )

    def get(self, request, *args, **kwargs):
        return Response({"text" : "Test"})


class PasswordChangeInsecureView(SecureAPIViewBaseView):
    serializer_class = PasswordChangeInsecureSerializer
    identity_directory_code = 'basic_internal'

    def post(self, request, *args, **kwargs):
        kwargs = super(PasswordChangeInsecureView, self).get_serializer_context()
        serializer = PasswordChangeInsecureSerializer(data=request.data, context=kwargs)
        if serializer.is_valid(raise_exception=False):
            if serializer.save():
                return Response({'text': 'Your password has been changed succesfully'})
            else:
                return Response({'text' : 'Your password has not been changed'})

        else:
            raise APIValidationError(detail=serializer.errors)