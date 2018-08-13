from django.template.loader import render_to_string
from django.urls import reverse
from rest_framework import serializers
from rest_framework import status
from talos.models import _tznow
from talos.models import BasicIdentity, BasicCredential, OneTimePasswordCredential
from talos.models import Principal, BasicIdentityDirectory, BasicCredentialDirectory, OneTimePasswordCredentialDirectory
from talos.models import ValidationToken
from talos_rest import constants
from talos_rest.validators import validate_email as  talos_rest_validate_email
from talos_rest.validators import validate_phone as talos_rest_validate_phone

PHONE_SMS_CREDENTIAL_DIRECTORY_CODE = 'onetimepassword_internal_phone_sms'
GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE = 'onetimepassword_internal_google_authenticator'


class OTPBaserSerializeMixin():
    def __init__(self, *args, **kwargs):
        self.fields['otp_code'] = serializers.CharField(label='SMS Code')
        self.otp_directory = None
        super(OTPBaserSerializeMixin, self).__init__(*args, **kwargs)

    def validate_otp_code(self, otp_code):
        otp_credential = self.principal.credentials.otp[0]
        self.otp_directory = otp_credential.directory

        # TODO: Should be removed
        if otp_code != '123456':
            raise serializers.ValidationError('OTP Code is incorrect',
                                              code='otp_code_incorrect')

        # if self.otp_directory.verify_credentials(self.principal,
        #                                                  {'code': otp_code}) == False:
        #     raise serializers.ValidationError('OTP code is incorrect',
        #                                       code=self.error_code)

class SMSOtpSerializerMixin(OTPBaserSerializeMixin):
    error_code = constants.SMS_OTP_INVALID_CODE
    directory_code = PHONE_SMS_CREDENTIAL_DIRECTORY_CODE


class GoogleOtpSerializerMixin(OTPBaserSerializeMixin):
    error_code = constants.GOOGLE_OTP_INVALID_CODE
    directory_code = GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE


class ValidatePasswordMixin():
    def __init__(self, *args, **kwargs):
        super(ValidatePasswordMixin, self).__init__(*args, **kwargs)
        self.fields['password'] = serializers.CharField(label='Password', max_length=255)
        self.password = None


    def validate_password(self, password):
        if not self.basic_credential_directory.verify_credentials(self.principal,
                                                                  {'password': password}):
            raise serializers.ValidationError('Password is incorrect',
                                              code=constants.PASSWORD_INVALID_CODE)
        self.password = password


class ValidateSecretWhenLogedInMixin():
    def __init__(self, *args, **kwargs):
        self.fields['secret'] = serializers.CharField(label='Token', max_length=255)
        self.token = None
        super(ValidateSecretWhenLogedInMixin, self).__init__(*args, **kwargs)

    def validate_secret(self, token):
        try:
            self.token = ValidationToken.objects.get(secret=token, type=self.token_type, expires_at__gt=_tznow(), is_active=True)
        except ValidationToken.DoesNotExist:
            self.token = None

        if not self.token or (self.token.principal != self.request.principal):
            raise serializers.ValidationError(
                'Token is not valid.',
                code=constants.TOKEN_INVALID_CODE)
        return token

class ValidateSecretWhenLoggedOutMixin():
    def __init__(self, *args, **kwargs):
        self.fields['secret'] = serializers.CharField(label='Token', max_length=255)
        self.token = None
        super(ValidateSecretWhenLoggedOutMixin, self).__init__(*args, **kwargs)

    def validate_secret(self, token):
        try:
            self.token = ValidationToken.objects.get(secret=token, type=self.token_type, expires_at__gt=_tznow(), is_active=True)
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError(
                'Token is not valid.',
                code=constants.TOKEN_INVALID_CODE)
        return self.token


class BasicSerializer(serializers.Serializer):
    BASIC_SUCCESS_CODE = status.HTTP_200_OK

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory

        self.request = None
        self.principal = None
        self.context_params = kwargs.get('context')
        if self.context_params.get('request'):
            self.request = self.context_params['request']
            if hasattr(self.request, 'principal'):
                self.principal = self.request.principal
        self.directory_code = self.context_params.get('directory_code')
        self.error_code = self.context_params.get('error_code')

        self.identity_directory_code = self.context_params.get('identity_directory_code')

        if self.identity_directory_code:
            self.basic_identity_directory = BasicIdentityDirectory.objects.get(
                code=self.identity_directory_code)
            self.basic_credential_directory = self.basic_identity_directory.credential_directory

        super(BasicSerializer, self).__init__(*args, **kwargs)

    def to_representation(self, instance):
        data = super(BasicSerializer, self).to_representation(instance)
        final_data = {'status': self.BASIC_SUCCESS_CODE,
                      'result': data}
        return final_data


class SessionSerializer(OTPBaserSerializeMixin, BasicSerializer):
    email = serializers.CharField(label='Email', help_text='Please enter email')
    password = serializers.CharField(label='Password', help_text='Please enter password')

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory
        super(SessionSerializer, self).__init__(*args, **kwargs)

        if self.request.method in ['POST']:
            self.fields['otp_code'].required = False
        else:
            self.fields['otp_code'].required = True
            self.fields['email'].required = False
            self.fields['password'].required = False

        self.identity_directory = BasicIdentityDirectory.objects.get(
            code=self.identity_directory_code)
        self.credential_directory = self.identity_directory.credential_directory
        self.evidences = list(self.credential_directory.provided_evidences.all().order_by('id'))

    def validate_email(self, value):
        email = value
        self.principal = self.identity_directory.get_principal({'username': email})

        if not self.principal:
            raise serializers.ValidationError(
                'Username is not valid. Note that username may be case-sensitive.',
                code=constants.USERNAME_INVALID_CODE)

        if not self.principal.is_active:
            raise serializers.ValidationError(
                'Username is valid, but account is disabled.',
                code=constants.ACCOUNT_INACTIVE_CODE)

        return email

    def validate_password(self, value):
        password = value
        if self.principal and (
                not self.credential_directory.verify_credentials(self.principal,
                                                                 {'password': password})):
            raise serializers.ValidationError(
                'Password is not valid. Note that password is case-sensitive.',
                code=constants.PASSWORD_INVALID_CODE)

    def save(self):
        if self.request.method in ['POST']:
            self.principal._load_authentication_context(self.evidences)
            self.request.principal = self.principal
        else:
            from talos.models import Evidence

            credential_directory = self.principal.credentials.otp[0].directory
            evidences = list(credential_directory.provided_evidences.all().order_by('id'))

            evidence_codes = [evidence.code for evidence in evidences]
            evidence_codes.extend(self.request.principal.get_current_evidence_code_list())
            provided_evidences = Evidence.objects.filter(code__in=evidence_codes)
            self.principal._load_authentication_context(provided_evidences)
            self.request.principal = self.principal


class GoogleAuthenticatorActivateRequestSerializer(ValidatePasswordMixin, BasicSerializer):
    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        super(GoogleAuthenticatorActivateRequestSerializer, self).__init__(*args, **kwargs)

        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        self.secret = None


    def validate(self, attrs):
        from talos.models import OneTimePasswordCredential

        try:
            self.otp_credential_directory.credentials.get(principal=self.principal,
                                                          directory=self.otp_credential_directory)
            raise serializers.ValidationError('User has already activated Google authenticator',
                                              code=constants.GOOGLE_OTP_EXISTS_CODE)
        except OneTimePasswordCredential.DoesNotExist:
            pass
        return attrs

    def save(self):
        from pyotp import random_base32

        secret = random_base32()
        self.request.session['temp_otp_secret_key'] = secret
        self.request.session['secret_key_activated'] = True
        self.secret = secret


class GoogleAuthenticatorActivateConfirmSerializer(BasicSerializer):
    code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        super(GoogleAuthenticatorActivateConfirmSerializer, self).__init__(*args, **kwargs)

        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        self.salt = None


    def validate_code(self, code):
        from pyotp import TOTP

        if not self.request.session.get('secret_key_activated', False):
            raise serializers.ValidationError('You did not activated google authenticator',
                                              code=constants.GOOGLE_OTP_NOT_ACTIVATED_CODE)

        totp = TOTP(self.request.session['temp_otp_secret_key'])
        if not totp.verify(code):
            raise serializers.ValidationError('Code is incorrect',
                                              code=constants.GOOGLE_OTP_INVALID_CODE)
        return code

    def save(self):
        if self.otp_credential_directory:
            self.otp_credential_directory.create_credentials(self.principal,
                                                             {'salt': self.request.session[
                                                              'temp_otp_secret_key']})
            self.salt = self.request.session['temp_otp_secret_key']
            del self.request.session['temp_otp_secret_key']
            del self.request.session['secret_key_activated']


class GoogleAuthenticatorDeleteRequestSerializer(BasicSerializer):
    token_type = 'otp_delete'

    def __init__(self, *args, **kwargs):
        super(GoogleAuthenticatorDeleteRequestSerializer, self).__init__(*args, **kwargs)

    def save(self):
        validation_token = ValidationToken()
        validation_token.identifier_type = 'email'
        validation_token.identifier_value = self.principal.email
        validation_token.principal = self.principal
        validation_token.type = self.token_type
        validation_token.save()


class GoogleAuthenticatorDeleteSerializer(GoogleOtpSerializerMixin,
                                          SMSOtpSerializerMixin,
                                          ValidatePasswordMixin,
                                          BasicSerializer):
    token = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        super(GoogleAuthenticatorDeleteSerializer, self).__init__(*args, **kwargs)

        self.validation_token = None
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        self.sms_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)


    def validate_token(self, token):
        try:
            email = self.principal.email
            self.validation_token = ValidationToken.objects.get(identifier='email',
                                                                identifier_value=email,
                                                                type='otp_delete',
                                                                secret=token,
                                                                is_active=True)
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError('Your token is invalid',
                                              code=constants.TOKEN_INVALID_CODE)
        return token

    def delete(self):
        if self.otp_credential_directory:
            self.otp_credential_directory.reset_credentials(self.principal,
                                                            self.principal,
                                                            {})
        self.validation_token.is_active = False
        self.validation_token.save()

class SendOTPSerializer(BasicSerializer):
    def save(self):
        principal = self.request.principal
        credential = principal.credentials.otp[0]
        directory = credential.directory
        directory.send_otp(principal, credential)



class EmailChangeRequestSerializer(BasicSerializer):
    token_type = 'email_change'

    new_email = serializers.CharField(label='New E-mail')

    def __init__(self, *args, **kwargs):
        super(EmailChangeRequestSerializer, self).__init__(*args, **kwargs)

    def validate_new_email(self, new_email):
        return talos_rest_validate_email(new_email, validate_uniqueness=True)


    def save(self):
        from talos_rest.utils import send_email

        new_email = self.validated_data['new_email']

        validation_token = ValidationToken()
        validation_token.identifier_type = 'email'
        validation_token.identifier_value = new_email
        validation_token.principal = self.request.principal
        validation_token.type = self.token_type
        validation_token.save()

        context = {
            'email' : new_email,
            'url': 'http://localhost:8000/email-change-validation/{}'.format(validation_token.secret)
        }

        send_email(context,
                   [new_email],
                   'talos/email_change/request_email_subject.txt',
                   'talos/email_change/request_email_body.txt',
                   'talos/email_change/request_email_body.html')


class EmailChangeValidationTokenCheckerSerializer(ValidateSecretWhenLogedInMixin, BasicSerializer):
    token_type = 'email_change'

    def __init__(self, *args, **kwargs):
        super(EmailChangeValidationTokenCheckerSerializer, self).__init__(*args, **kwargs)


class EmailChangeBaseSerialize(OTPBaserSerializeMixin,
                               ValidatePasswordMixin,
                               ValidateSecretWhenLogedInMixin,
                               BasicSerializer):
    token_type = 'email_change'

    def __init__(self, *args, **kwargs):
        super(EmailChangeBaseSerialize, self).__init__(*args, **kwargs)

    def save(self):
        from talos.models import BasicIdentity
        from talos.contrib.sms_sender import SMSSender
        from talos_rest.utils import send_email

        old_email = self.token.principal.email

        self.token.principal.email = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        basic_identity = BasicIdentity.objects.get(principal=self.principal)
        basic_identity.username = self.token.identifier_value
        basic_identity.save()
        # Remove session to logout
        self.request.session.flush()

        context = {
            'email': self.token.principal.email,
        }

        send_email(context, [self.token.principal.email, old_email],
                   'talos/email_change/confirmed_email_subject.txt',
                   'talos/email_change/confirmed_email_body.txt',
                   'talos/email_change/confirmed_email_body.html')


        mail_change_text = render_to_string('talos/email_change/confirmed_email_body_mobile.txt')
        sms_sender = SMSSender()
        sms_sender.send_message(self.token.principal.phone, mail_change_text)


class EmailResetRequestSerializer(BasicSerializer):
    old_email = serializers.CharField(label='Old E-mail')
    new_email = serializers.CharField(label='New E-mail')
    token_type = 'email_reset'

    def __init__(self, *args, **kwargs):
        super(EmailResetRequestSerializer, self).__init__(*args, **kwargs)

    def validate_new_email(self, new_email):
        return talos_rest_validate_email(new_email, validate_uniqueness=True)


    def validate_old_email(self, email):
        return talos_rest_validate_email(email, validate_existance=True)


    def save(self):
        from talos_rest.utils import send_email

        new_email = self.validated_data['new_email']
        old_email = self.validated_data['old_email']

        validation_token = ValidationToken()
        validation_token.identifier_type = 'email'
        validation_token.identifier_value = new_email
        principal = Principal.objects.get(email=old_email)
        validation_token.principal = principal
        validation_token.type = self.token_type
        validation_token.save()

        url = '{0}://{1}{2}'.format(
            self.request.scheme,
            self.request.META.get('HTTP_HOST', 'test_host'),
            reverse('email-reset-token-validation', args=[validation_token.secret])
        )

        context = {
            'email': new_email,
            'url': url,
            'recipient_name' : self.request.principal.full_name
        }

        send_email(context, [self.token.principal.email],
                   'talos/email_reset/request_email_reset_subject.txt',
                   'talos/email_reset/request_email_reset_body.txt',
                   'talos/email_reset/request_email_reset_body.html')


class EmailResetValidationTokenCheckerSerializer(ValidateSecretWhenLoggedOutMixin, BasicSerializer):
    token_type = 'email_reset'

    def __init__(self, *args, **kwargs):
        super(EmailResetValidationTokenCheckerSerializer, self).__init__(*args, **kwargs)


class EmailResetBaseSerializer(BasicSerializer):
    token_type = 'email_reset'
    token = serializers.CharField(label='Token')

    def __init__(self, *args, **kwargs):
        super(EmailResetBaseSerializer, self).__init__(*args, **kwargs)

    def validate_token(self, token):
        try:
            self.token = ValidationToken.objects.get(secret=token, type=self.token_type, expires_at__gt=_tznow(), is_active=True)
            self.principal = self.token.principal
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError(
                'Token is not valid.',
                code=constants.TOKEN_INVALID_CODE)
        return self.token

    def save(self):
        from talos.models import BasicIdentity
        from talos.contrib.sms_sender import SMSSender
        from talos_rest.utils import send_email

        self.token.principal.email = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        basic_identity = BasicIdentity.objects.get(principal=self.principal)
        basic_identity.username = self.token.identifier_value
        basic_identity.save()


        context = {
            'email': self.principal.email
        }

        send_email(context,
                   [self.token.principal.email],
                   'talos/email_reset/confirmed_email_reset_subject.txt',
                   'talos/email_reset/confirmed_email_reset_body.txt',
                   'talos/email_reset/confirmed_email_reset_body.html')


        phone_text = render_to_string('talos/email_reset/confirmed_email_reset_mobile.txt')
        sms_sender = SMSSender()
        sms_sender.send_message(self.token.principal.phone, phone_text)


class PhoneChangeRequestSerializer(BasicSerializer):
    token_type = 'phone_change'

    new_phone = serializers.CharField(label='New Phone')

    def __init__(self, *args, **kwargs):
        super(PhoneChangeRequestSerializer, self).__init__(*args, **kwargs)

    def validate_new_phone(self, new_phone):
        return talos_rest_validate_phone(new_phone, validate_uniqueness=True)

    def save(self):
        from talos_rest.utils import send_email

        new_phone = self.validated_data['new_phone']

        validation_token = ValidationToken()
        validation_token.identifier_type = 'phone'
        validation_token.identifier_value = new_phone
        validation_token.principal = self.request.principal
        validation_token.type = self.token_type
        validation_token.save()

        url = '{0}://{1}{2}'.format(
            self.request.scheme,
            self.request.META.get('HTTP_HOST', 'test_host'),
            reverse('phone-change-token-validation', args=[validation_token.secret])
        )

        context = {
            'email': self.principal.email,
            'url': url
        }

        send_email(context,
                  [self.token.principal.email],
                  'talos/phone_change/request_phone_subject.txt',
                  'talos/phone_change/request_phone_body.txt',
                  'talos/phone_change/request_phone_body.html')

class PhoneChangeValidationTokenCheckerSerializer(ValidateSecretWhenLogedInMixin, BasicSerializer):
    token_type = 'phone_change'

    def __init__(self, *args, **kwargs):
        super(PhoneChangeValidationTokenCheckerSerializer, self).__init__(*args, **kwargs)


class PhoneChangeBaseSerialize(BasicSerializer):
    token_type = 'phone_change'

    def __init__(self, *args, **kwargs):
        super(PhoneChangeBaseSerialize, self).__init__(*args, **kwargs)

    def save(self):
        from talos.contrib.sms_sender import SMSSender

        self.token.principal.phone = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        phone_text = render_to_string('talos/phone_change/confirmed_phone_change.txt')
        sms_sender = SMSSender()
        sms_sender.send_message(self.token.principal.phone, phone_text)


class PhoneResetRequestSerializer(BasicSerializer):
    token_type = 'phone_reset'

    email = serializers.CharField(label='Email', max_length=255)
    new_phone = serializers.CharField(label='New Phone', max_length=255)

    def __init__(self, *args, **kwargs):
        super(PhoneResetRequestSerializer, self).__init__(*args, **kwargs)

    def validate_new_phone(self, new_phone):
        return talos_rest_validate_phone(new_phone, validate_uniqueness=True)


    def validate_email(self, email):
        return talos_rest_validate_email(email, validate_existance=True)

    def save(self):
        from talos_rest.utils import send_email

        new_phone = self.validated_data['new_phone']
        email = self.validated_data['email']

        validation_token = ValidationToken()
        validation_token.identifier_type = 'phone'
        validation_token.identifier_value = new_phone
        principal = Principal.objects.get(email=email)
        validation_token.principal = principal
        validation_token.type = self.token_type
        validation_token.save()

        url = '{0}://{1}{2}'.format(
            self.request.scheme,
            self.request.META.get('HTTP_HOST', 'test_host'),
            reverse('phone-reset-token-validation', args=[validation_token.secret])
        )

        context = {
            'email': self.principal.email,
            'url': url
        }

        send_email(context,
                   [self.token.principal.email],
                   'talos/phone_reset/request_phone_reset_subject.txt',
                   'talos/phone_reset/request_phone_reset_body.txt',
                   'talos/phone_reset/request_phone_reset_body.html')


class PhoneResetValidationTokenCheckerSerializer(ValidateSecretWhenLoggedOutMixin, BasicSerializer):
    token_type = 'phone_reset'

    def __init__(self, *args, **kwargs):
        super(PhoneResetValidationTokenCheckerSerializer, self).__init__(*args, **kwargs)


class PhoneResetBaseSerialize(OTPBaserSerializeMixin, ValidatePasswordMixin, BasicSerializer):
    token_type = 'phone_reset'
    token = serializers.CharField(label='Token')

    def __init__(self, *args, **kwargs):
        super(PhoneResetBaseSerialize, self).__init__(*args, **kwargs)

    def validate_token(self, token):
        try:
            self.token = ValidationToken.objects.get(secret=token, type=self.token_type, expires_at__gt=_tznow(), is_active=True)
            self.principal = self.token.principal
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError(
                'Token is not valid.',
                code=constants.TOKEN_INVALID_CODE)

    def save(self):
        from talos.contrib.sms_sender import SMSSender

        self.token.principal.phone = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        phone_text = render_to_string('talos/phone_reset/confirmed_phone_reset_phone.txt')
        sms_sender = SMSSender()
        sms_sender.send_message(self.token.principal.phone, phone_text)

class PasswordResetRequestSerializer(BasicSerializer):
    email = serializers.CharField()

    token_type = 'password_reset'

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        super(PasswordResetRequestSerializer, self).__init__(*args, **kwargs)

        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)


    def validate_email(self, email):
        try:
            principal = Principal.objects.get(email=email)
            self.principal = principal
        except Principal.DoesNotExist:
            raise serializers.ValidationError("Email doesn't exists",
                                              code=constants.EMAIL_INVALID_CODE)
        return email

    def save(self):
        from talos_rest.utils import send_email

        email = self.validated_data['email']

        validation_token = ValidationToken()
        validation_token.identifier_type = 'email'
        validation_token.identifier_value = email
        validation_token.principal = self.principal
        validation_token.type = self.token_type
        validation_token.save()

        self.token = validation_token

        url = '{0}://{1}{2}'.format(
            self.request.scheme,
            self.request.META.get('HTTP_HOST', 'test_host'),
            '/account/reset-password-token#{0}'.format(validation_token.secret)
        )

        context = {
            'email': email,
            'url': url,
            'recipient_name': validation_token.principal.full_name,
        }

        send_email(context,
                   [email],
                   'talos/email_change/request_email_subject.txt',
                   'talos/email_change/request_email_body.txt',
                   'talos/email_change/request_email_body.html')


class PasswordResetValidationTokenSerializer(ValidateSecretWhenLoggedOutMixin,
                                            BasicSerializer):
    token_type = 'password_reset'

    def __init__(self, *args, **kwargs):
        super(PasswordResetValidationTokenSerializer, self).__init__(*args, **kwargs)

    def save(self):
        principal = self.token.principal
        otp_credential = principal.credentials.otp[0]
        otp_directory = otp_credential.directory
        otp_directory.send_otp(principal, otp_credential)


class PasswordResetBaseSerializer(OTPBaserSerializeMixin, BasicSerializer):
    secret = serializers.CharField()
    password = serializers.CharField()

    token_type = 'password_reset'

    def __init__(self, *args, **kwargs):
        super(PasswordResetBaseSerializer, self).__init__(*args, **kwargs)
        self.validation_token = None


    def validate_secret(self, secret):
        try:
            validation_token = ValidationToken.objects.get(secret=secret,
                                                           is_active=True,
                                                           type=self.token_type)
            self.validation_token = validation_token
            self.principal = self.validation_token.principal
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError("Secret doesn't exits",
                                              code=constants.TOKEN_INVALID_CODE)
        return secret

    def validate_password(self, password):
        from talos_rest.validators import validate_password

        validate_password(password)

        return password

    def save(self):
        password = self.validated_data['password']

        if self.principal and self.basic_credential_directory:
            self.basic_credential_directory.reset_credentials(self.principal,
                                                              self.principal,
                                                              {'password': password})

        if self.validation_token:
            self.validation_token.is_active = False
            self.validation_token.save()


class PasswordChangeBaseSerialize(OTPBaserSerializeMixin, ValidatePasswordMixin, BasicSerializer):
    new_password = serializers.CharField()

    def __init__(self, *args, **kwargs):
        super(PasswordChangeBaseSerialize, self).__init__(*args, **kwargs)

    def validate_new_password(self, new_password):
        from talos_rest.validators import validate_password

        validate_password(new_password)

        return new_password

    def save(self):
        from talos.models import Session
        from django.db.models import Q
        from django.utils import timezone

        # Delete every other active session user has
        Session.objects.filter(Q(principal=self.request.principal),
                               ~Q(uuid=self.request.session._session.uuid),
                               Q(valid_till__gt=timezone.now())).update(evidences=None)

        new_password = self.validated_data['new_password']
        return self.basic_credential_directory.update_credentials(self.principal,
                                                                  {'password': self.password},
                                                                  {'password': new_password})



class RegistrationRequestSerializer(BasicSerializer):
    brief_name = serializers.CharField(max_length=250, required=False)
    full_name = serializers.CharField(max_length=250, required=False)
    username = serializers.CharField(max_length=250, required=False)
    email = serializers.CharField(max_length=250, required=False)
    phone = serializers.CharField(max_length=250, required=False)
    password = serializers.CharField(max_length=250, required=False)

    def validate_brief_name(self, brief_name):
        return brief_name

    def validate_full_name(self, full_name):
        return full_name

    def validate_email(self, email):
        return talos_rest_validate_email(email, validate_uniqueness=True)

    def validate_phone(self, phone):
        return talos_rest_validate_phone(phone, validate_uniqueness=True)

    def validate_password(self, password):
        return password

    def validate(self, attrs):
        if not attrs.get('phone') and not attrs.get('email'):
            raise serializers.ValidationError('Phone or Email should be provided',
                                              'email_or_phone_required')

        return attrs


    def save(self):
        from uuid import uuid4
        import json
        from talos.models import _tzmin
        from talos.models import _tzmax
        from talos.helpers.session import CustomJSONEncoder
        import pyotp

        principal = Principal()
        if self.validated_data.get('brief_name'):
            principal.brief_name = self.validated_data.get('brief_name')
        principal.full_name = self.validated_data.get('full_name', None)
        principal.email = self.validated_data.get('email', None)
        principal.phone = self.validated_data.get('phone', None)

        uuid_str = str(principal.uuid)

        if self.validated_data.get('username'):
            basic_identity = BasicIdentity()
            basic_identity.uuid = uuid4()
            basic_identity.principal = principal
            basic_identity.directory = BasicIdentityDirectory.objects.get(code='basic_internal')
            basic_identity.username = self.validated_data['username']

            principal.identities.basic.append(basic_identity)

        if self.validated_data.get('password'):
            basic_credential = BasicCredential()
            basic_credential.uuid = uuid4()
            basic_credential.principal = principal
            basic_credential.directory = BasicCredentialDirectory.objects.get(code='basic_internal')
            basic_credential.algorithm_name = 'pbkdf2'
            basic_credential.algorithm_rounds = 100000
            basic_credential.valid_from = _tzmin()
            basic_credential.valid_till = _tzmax()
            basic_credential.force_change = False
            basic_credential.set_password(self.validated_data['password'])

            principal.credentials.basic.append(basic_credential)

        if self.validated_data.get('phone'):
            otp_credential = OneTimePasswordCredential()
            otp_credential.uuid = uuid4()
            otp_credential.principal = principal
            otp_credential.valid_till = _tzmin()
            otp_credential.valid_till = _tzmax()
            otp_credential.directory = OneTimePasswordCredentialDirectory.objects.get(code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)
            salt = pyotp.random_base32()
            otp_credential.salt = salt

            principal.credentials.otp.append(otp_credential)

        serialized = json.dumps(principal, cls=CustomJSONEncoder)

        self.request.session[uuid_str] = serialized
        self.uuid = uuid_str


class RegistrationConfirmationSerializer(BasicSerializer):
    is_completed = serializers.BooleanField(default=False)
    token = serializers.CharField(max_length=250)
    code = serializers.CharField(max_length=100)

    brief_name = serializers.CharField(max_length=250, required=False)
    full_name = serializers.CharField(max_length=250, required=False)
    email = serializers.CharField(max_length=250, required=False)
    phone = serializers.CharField(max_length=250, required=False)
    password = serializers.CharField(max_length=250, required=False)

    extra = serializers.DictField(required=False)

    def validate_email(self, email):
        return talos_rest_validate_email(email, validate_uniqueness=True)

    def validate_phone(self, phone):
        return talos_rest_validate_phone(phone, validate_uniqueness=True)

    def validate(self, attrs):
        import json
        from talos.helpers.session import CustomJSONDecoder

        token = attrs['token']
        code = attrs['code']

        if not self.request.session.get(token):
            raise serializers.ValidationError('Your token is invalid',
                                              code=constants.TOKEN_INVALID_CODE)

        self.principal = json.loads(self.request.session[token], cls=CustomJSONDecoder)

        otp_credential = self.principal.credentials.otp[0]

        otp_directory = otp_credential.directory

        if code != '123456':
            raise serializers.ValidationError('Code is incorrect',
                                              code=constants.OTP_INVALID)

        #if not otp_directory.verify_otp(self.principal, self.principal.otp_credential, code):
        #    raise serializers.ValidationError('Code is incorrect',
        #                                      code=constants.OTP_INVALID)

        return attrs

    def save(self):
        import json
        from talos.helpers.session import CustomJSONEncoder
        from talos_rest.signals import pre_registration
        from talos_rest.signals import post_registration

        token = self.validated_data['token']
        is_completed = self.validated_data['is_completed']

        if self.validated_data.get('brief_name'):
            self.principal.brief_name = self.validated_data['brief_name']

        if self.validated_data.get('full_name'):
            self.principal.full_name = self.validated_data['full_name']

        if self.validated_data.get('email'):
            self.principal.email = self.validated_data['email']

        if self.validated_data.get('phone'):
            self.principal.phone = self.validated_data['phone']

        if self.validated_data.get('email'):
            self.basic_identity.username = self.validated_data['email']

        if self.validated_data.get('password'):
            self.basic_credential.set_password(self.validated_data['password'])


        if is_completed:
            extra = self.validated_data.get('extra', {})
            try:
                try:
                    pre_registration.send(sender=self.principal.__class__, extra=extra, principal=self.principal)
                except Exception as e:
                    raise serializers.ValidationError(e)
                self.principal.save()
                post_registration.send(sender=self.principal.__class__, extra=extra, principal=self.principal)
            except Exception as e:
                print(e)
                raise serializers.ValidationError('Something went wrong while saving principal',
                                                  code='internal_error')

            del self.request.session[token]
        else:
            try:
                self.request.session[token] = json.dumps(self.principal, cls=CustomJSONEncoder)
            except Exception as e:
                raise serializers.ValidationError('Something went wrong while serializing principal object',
                                                  code='internal_error')


class RegistrationMessageSerializer(BasicSerializer):
    token = serializers.CharField()

    def validate_token(self, token):
        if self.request.session.get(token, None) == None:
            raise serializers.ValidationError('Your token is invalid', code=constants.TOKEN_INVALID_CODE)
        return token

    def send(self):
        import json
        from talos.helpers.session import CustomJSONDecoder

        token = self.validated_data['token']
        principal = json.loads(self.request.session[token], cls=CustomJSONDecoder)

        otp_credential = principal.credentials.otp[0]
        otp_directory = otp_credential.directory
        otp_directory.send_otp(principal, otp_credential)

        self.token = self.validated_data['token']

class EmailActivationRequestSerializer(BasicSerializer):
    def save(self):
        from talos.models import ValidationToken
        from talos_rest.utils import send_email

        email = self.principal.email

        validation_token = ValidationToken()
        validation_token.identifier_type = 'email'
        validation_token.identifier_value = email
        validation_token.principal = self.principal
        validation_token.type = 'email_activation'
        validation_token.save()

        url = '{0}://{1}{2}'.format(
            self.request.scheme,
            self.request.META.get('HTTP_HOST', 'test_host'),
            '/account/email-activation/{0}'.format(validation_token.secret)
        )

        context = {
            'email': email,
            'url': url,
            'recipient_name': validation_token.principal.full_name,
        }

        send_email(context,
                   [email],
                   'talos/email_activation/email_activation_request_subject.txt',
                   'talos/email_activation/email_activation_request_body.txt',
                   'talos/email_activation/email_activation_request_body.html')


class EmailActivationConfirmationSerializer(BasicSerializer):
    secret = serializers.CharField(max_length=250) 
    
    def validate_secret(self, secret): 
        from talos.models import ValidationToken
        try:
            self.validation_token = ValidationToken.objects.get(secret=secret,
                                                                is_active=True)
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError('Your token is invalid',
                                              constants.TOKEN_INVALID_CODE)
        return secret 
    
    def save(self):
        self.validation_token.is_active = False
        self.validation_token.save()

        self.principal.is_email_verified = True
        self.principal.save()
