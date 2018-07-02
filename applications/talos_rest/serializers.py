from re import compile
from rest_framework import serializers
from talos.models import Principal
from talos.models import ValidationToken
from talos.models import _tznow
from rest_framework import status
from talos_rest import constants

email_regex = compile(r'^[^@]+@[^@]+\.[^@]+$')

PHONE_SMS_CREDENTIAL_DIRECTORY_CODE = 'onetimepassword_internal_phone_sms_authenticator'
GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE = 'onetimepassword_internal_google_authenticator'


###
### Start of mixins
###
class SMSOtpSerializerMixin():

    def __init__(self, *args, **kwargs):
        self.fields['sms_code'] = serializers.CharField(label='SMS Code')
        self.sms_otp_directory = None
        super(SMSOtpSerializerMixin, self).__init__(*args, **kwargs)

    def validate_sms_code(self, sms_code):
        from talos.models import OneTimePasswordCredentialDirectory

        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)

        if not self.sms_otp_directory.verify_credentials(self.principal,
                                                         {'code': sms_code}):
            raise serializers.ValidationError('OTP code is incorrect',
                                              code=constants.SMS_OTP_INVALID_CODE)


class GoogleOtpSerializerMixin():
    def __init__(self, *args, **kwargs):
        self.fields['google_otp_code'] = serializers.CharField(label='Google OTP Code',
                                                               max_length=255)
        self.otp_directory = None
        super(GoogleOtpSerializerMixin, self).__init__(*args, **kwargs)

    def validate_google_otp_code(self, google_otp_code):
        from talos.models import OneTimePasswordCredentialDirectory
        self.otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        if not self.otp_directory.verify_credentials(self.principal,
                                                     {'code': google_otp_code}):
            raise serializers.ValidationError('OTP code is incorrect',
                                              code=constants.GOOGLE_OTP_INVALID_CODE)


class ValidatePasswordMixin():

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory
        self.fields['password'] = serializers.CharField(label='Password', max_length=255)
        passed_kwargs_from_view = kwargs.get('context')
        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory
        self.password = None
        super(ValidatePasswordMixin, self).__init__(*args, **kwargs)

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

    token_type = None

    def validate_secret(self, token):
        """ Validate token"""
        try:
            self.token = ValidationToken.objects.get(
                secret=token,
                type=self.token_type,
                expires_at__gt=_tznow(),
                is_active=True
            )

        except ValidationToken.DoesNotExist:
            self.token = None

        if not self.token or (self.token.principal != self.request.principal):
            raise serializers.ValidationError(
                'Token is not valid.',
                code=constants.TOKEN_INVALID_CODE)


class ValidateSecretWhenLoggedOutMixin():
    def __init__(self, *args, **kwargs):
        self.fields['secret'] = serializers.CharField(label='Token', max_length=255)
        self.token = None
        super(ValidateSecretWhenLoggedOutMixin, self).__init__(*args, **kwargs)

    token_type = None

    def validate_secret(self, token):
        """ Validate token"""
        try:
            self.token = ValidationToken.objects.get(
                secret=token,
                type=self.token_type,
                expires_at__gt=_tznow(),
                is_active=True
            )

        except ValidationToken.DoesNotExist:
            self.token = None

        if not self.token:
            raise serializers.ValidationError(
                'Token is not valid.',
                code=constants.TOKEN_INVALID_CODE)
        return self.token


####
#### Endof the mixins
####

class BasicSerializer(serializers.Serializer):
    BASIC_SUCCESS_CODE = status.HTTP_200_OK

    def to_representation(self, instance):
        data = super(BasicSerializer, self).to_representation(instance)
        final_data = {'status': self.BASIC_SUCCESS_CODE,
                      'result': data}
        return final_data


class SessionSerializer(BasicSerializer):
    email = serializers.CharField(label='Email', help_text='Please enter email')
    password = serializers.CharField(label='Password', help_text='Please enter password')

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.evidences = list(self.credential_directory.provided_evidences.all().order_by('id'))
        self.request = passed_kwargs_from_view['request']
        self.principal = None
        del passed_kwargs_from_view['identity_directory_code']
        del passed_kwargs_from_view['request']

        super(SessionSerializer, self).__init__(*args, **kwargs)

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

        # return password

    def save(self):
        self.principal._load_authentication_context(self.evidences)
        self.request.principal = self.principal


class GoogleAuthenticatorActivateRequestSerializer(ValidatePasswordMixin, BasicSerializer):
    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        self.secret = None
        super(GoogleAuthenticatorActivateRequestSerializer, self).__init__(*args, **kwargs)

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


class GoogleAuthenticatorActivateConfirmSerializer(serializers.Serializer):
    code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        self.salt = None
        super(GoogleAuthenticatorActivateConfirmSerializer, self).__init__(*args, **kwargs)

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


class GoogleAuthenticatorDeleteRequestSerializer(serializers.Serializer):
    token_type = 'otp_delete'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        super(GoogleAuthenticatorDeleteRequestSerializer, self).__init__(*args, **kwargs)

    def save(self):
        validation_token = ValidationToken()
        validation_token.identifier = 'email'
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
        from talos.models import BasicIdentityDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.validation_token = None
        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        self.sms_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)
        super(GoogleAuthenticatorDeleteSerializer, self).__init__(*args, **kwargs)

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


class GoogleAuthenticatorChangeRequestSerializer(BasicSerializer):
    token_type = 'otp_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        super(GoogleAuthenticatorChangeRequestSerializer, self).__init__(*args, **kwargs)

    def save(self):
        validation_token = ValidationToken()
        validation_token.principal = self.principal
        validation_token.identifier = 'email'
        validation_token.identifier_value = self.principal.email
        validation_token.type = self.token_type
        validation_token.save()


class GoogleAuthenticatorChangeConfirmSerializer(BasicSerializer):
    token = serializers.CharField()
    password = serializers.CharField()
    otp_code = serializers.CharField()
    sms_code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        self.sms_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)
        self.salt = None
        super(GoogleAuthenticatorChangeConfirmSerializer, self).__init__(*args, **kwargs)

    def validate_token(self, token):
        try:
            token = ValidationToken.objects.get(secret=token,
                                                is_active=True,
                                                email=self.principal.email)
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError('Token is incorrect',
                                              code=constants.TOKEN_INVALID_CODE)
        return token

    def validate_password(self, password):
        if self.basic_credential_directory \
                and not self.basic_credential_directory.verify_credentials(self.principal,
                                                                           {'password': password}):
            raise serializers.ValidationError('Password is incorrect',
                                              code=constants.PASSWORD_INVALID_CODE)
        return password

    def validate_otp_code(self, otp_code):
        if self.otp_credential_directory \
                and not self.otp_credential_directory.verify_credentials(self.principal,
                                                                         {'code': otp_code}):
            raise serializers.ValidationError('OTP Code is incorrect',
                                              code=constants.GOOGLE_OTP_INVALID_CODE)
        return otp_code

    def validate_sms_code(self, sms_code):
        if self.sms_credential_directory \
                and not self.sms_credential_directory.verify_credentials(self.principal,
                                                                         {'code': sms_code}):
            raise serializers.ValidationError('SMS code is incorrect',
                                              code=constants.SMS_OTP_INVALID_CODE)
        return sms_code

    def save(self):
        from pyotp import random_base32

        self.request.session['otp_verified'] = True
        self.request.session['temp_otp_token'] = random_base32()
        self.salt = self.request.session['temp_otp_token']


class GoogleAuthenticatorChangeDoneSerializer(BasicSerializer):
    otp_code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        self.sms_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)
        super(GoogleAuthenticatorChangeDoneSerializer, self).__init__(*args, **kwargs)

    def validate_otp_code(self, otp_code):
        from pyotp import TOTP

        if not self.request.session.get('otp_verified', None) \
                or not self.request.session.get('temp_otp_token', None):
            raise serializers.ValidationError('OTP credentials is not verified',
                                              code=constants.GOOGLE_OTP_NOT_REQUESTED_CODE)

        totp = TOTP(self.request.session.get('temp_otp_token', None))
        if not totp.verify(otp_code):
            raise serializers.ValidationError('OTP Code is incorrect',
                                              code=constants.GOOGLE_OTP_INVALID_CODE)
        return otp_code

    def save(self):
        if self.otp_credential_directory:
            temp_otp_token = self.request.session['temp_otp_token']
            new_credentials = {'salt': temp_otp_token}
            self.otp_credential_directory.update_credentials(self.principal,
                                                             old_credentials=None,
                                                             new_credentials=new_credentials)


class GeneratePhoneCodeForAuthorizedUserSerializer(serializers.Serializer):

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)
        super(GeneratePhoneCodeForAuthorizedUserSerializer, self).__init__(*args, **kwargs)

    def save(self):
        if self.sms_otp_directory:
            self.sms_otp_directory.create_credentials(self.principal, {})


class VerifyPhoneCodeForAuthorizedUserSerializer(serializers.Serializer):
    code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)
        self.sms_otp_evidences = self.sms_otp_directory.provided_evidences.all().order_by('-id')
        super(VerifyPhoneCodeForAuthorizedUserSerializer, self).__init__(*args, **kwargs)

    def validate_code(self, code):
        if self.sms_otp_directory and not self.sms_otp_directory.verify_credentials(self.principal,
                                                                                    {'code': code}):
            raise serializers.ValidationError('Code is incorrect',
                                              code=constants.SMS_OTP_INVALID_CODE)
        return code

    def save(self):
        for sms_otp_evidence in self.sms_otp_evidences:
            self.principal._evidences_effective[sms_otp_evidence.code] = sms_otp_evidence


class ChangePasswordInsecureSerializer(BasicSerializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()
    sms_code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import BasicIdentityDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)
        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory
        super(ChangePasswordInsecureSerializer, self).__init__(*args, **kwargs)

    def validate_full_name(self, full_name):
        return full_name

    def validate_sms_code(self, sms_code):
        if not self.sms_otp_directory.verify_credentials(self.principal,
                                                         {'code': sms_code}):
            raise serializers.ValidationError('Sms Code is incorrect',
                                              code=constants.SMS_OTP_INVALID_CODE)
        return sms_code

    def validate_old_password(self, old_password):
        if not self.basic_credential_directory.verify_credentials(self.principal,
                                                                  {'password': old_password}):
            raise serializers.ValidationError('Password is incorrect',
                                              code=constants.PASSWORD_INVALID_CODE)
        return old_password

    def validate(self, attrs):
        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError('Passwords must be different',
                                              code=constants.PASSWORD_NOT_MATCH)
        return attrs

    def save(self):
        old_credentials = {'password': self.validated_data['old_password']}
        new_credentials = {'password': self.validated_data['new_password']}
        self.basic_credential_directory.update_credentials(self.principal,
                                                           old_credentials=old_credentials,
                                                           new_credentials=new_credentials)


class ChangePasswordSecureSerializer(BasicSerializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()
    otp_code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import BasicIdentityDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory
        super(ChangePasswordSecureSerializer, self).__init__(*args, **kwargs)

    def validate_old_password(self, old_password):
        if not self.basic_credential_directory.verify_credentials(self.principal,
                                                                  {'password': old_password}):
            raise serializers.ValidationError('Password is incorrect',
                                              code=constants.PASSWORD_INVALID_CODE)
        return old_password

    def validate(self, attrs):
        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError('Passwords must be different',
                                              code=constants.PASSWORD_NOT_MATCH)
        return attrs

    def validate_otp_code(self, otp_code):
        if not self.otp_directory.verify_credentials(self.principal,
                                                     {'code': otp_code}):
            raise serializers.ValidationError('Sms Code is incorrect',
                                              code=constants.SMS_OTP_INVALID_CODE)
        return otp_code

    def save(self):
        old_credentials = {'password': self.validated_data['old_password']}
        new_credentials = {'password': self.validated_data['new_password']}
        self.basic_credential_directory.update_credentials(self.principal,
                                                           old_credentials=old_credentials,
                                                           new_credentials=new_credentials)


class AddSMSEvidenceSerializer(SMSOtpSerializerMixin, BasicSerializer):
    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)
        self.sms_otp_evidences = self.sms_otp_directory.provided_evidences.all().order_by('-id')
        super(AddSMSEvidenceSerializer, self).__init__(*args, **kwargs)

    def save(self):
        from talos.models import Evidence

        evidence_codes = [evidence.code for evidence in self.sms_otp_evidences]
        evidence_codes.extend(self.principal.get_current_evidence_code_list())
        provided_evidences = Evidence.objects.filter(code__in=evidence_codes)
        self.principal._load_authentication_context(provided_evidences)


class AddGoogleEvidenceSerializer(GoogleOtpSerializerMixin, serializers.Serializer):

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        self.otp_evidences = self.otp_credential_directory.provided_evidences.all().order_by('id')
        super(AddGoogleEvidenceSerializer, self).__init__(*args, **kwargs)

    def save(self):
        from talos.models import Evidence

        evidence_codes = [evidence.code for evidence in self.otp_evidences]
        evidence_codes.extend(self.principal.get_current_evidence_code_list())
        provided_evidences = Evidence.objects.filter(code__in=evidence_codes)
        self.principal._load_authentication_context(provided_evidences)


class GeneratePhoneCodeForUnAuthorizedUserSerializer(BasicSerializer):
    phone = serializers.CharField()

    def validate_phone(self, phone):
        from talos_rest.validators import validate_phone

        validate_phone(phone)

        if Principal.objects.filter(phone=phone).count() > 0:
            raise serializers.ValidationError('This mobile phone is already user',
                                              code=constants.PHONE_USED_CODE)
        return phone

    def save(self):
        from talos.contrib.sms_sender import SMSSender
        from pyotp import random_base32
        from pyotp import TOTP

        phone = self.validated_data['phone']
        phone_validation_token = ValidationToken()
        phone_validation_token.identifier = 'phone'
        phone_validation_token.identifier_value = phone
        phone_validation_token.type = 'principal_registration'
        secret_key = random_base32()
        phone_validation_token.secret = secret_key
        phone_validation_token.save()

        totp = TOTP(secret_key)
        sms_sender = SMSSender()
        if not sms_sender.send_message(phone, 'You registration code is {}'.format(totp.now())):
            raise serializers.ValidationError('This mobile phone is invalid',
                                              code=constants.PHONE_INVALID_CODE)


class VerifyPhoneCodeForUnAuthorizedUserSerializer(BasicSerializer):
    phone = serializers.CharField()
    code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        self.phone = None
        self.token = None
        super(VerifyPhoneCodeForUnAuthorizedUserSerializer, self).__init__(*args, **kwargs)

    def validate_phone(self, phone):
        try:
            ValidationToken.objects.get(identifier='phone',
                                        identifier_value=phone,
                                        type='principal_registration',
                                        is_active=True)
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError('Phone does not exists',
                                              code=constants.PHONE_INVALID_CODE)
        self.phone = phone

        return phone

    def validate_code(self, code):
        from pyotp import TOTP

        try:
            validation_token = ValidationToken.objects.filter(
                identifier='phone',
                identifier_value=self.phone,
                type='principal_registration',
                is_active=True).order_by('-id')

            if validation_token.count() > 0:
                validation_token = validation_token[0]
            else:
                raise serializers.ValidationError('Code is incorrect',
                                                  code=constants.SMS_OTP_INVALID_CODE)
            secret_key = validation_token.secret
            totp = TOTP(secret_key)

            if not totp.verify(code):
                raise serializers.ValidationError('Code is incorrect',
                                                  code=constants.SMS_OTP_INVALID_CODE)
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError('Code is incorrect',
                                              code=constants.SMS_OTP_INVALID_CODE)
        return code

    def validate(self, attrs):
        from pyotp import TOTP

        phone = attrs['phone']
        code = attrs['code']

        try:
            phone_validation_token = ValidationToken.objects.filter(
                identifier='phone',
                identifier_value=phone,
                type='principal_registration',
                is_active=True).order_by('-id')

            if phone_validation_token.count() > 0:
                phone_validation_token = phone_validation_token[0]
            else:
                raise serializers.ValidationError(
                    'Your code is incorect',
                    code=constants.TOKEN_INVALID_CODE)

            secret_key = phone_validation_token.secret
            totp = TOTP(secret_key)

            if not totp.verify(code):
                raise serializers.ValidationError(
                    'Your code is incorrect',
                    code=constants.TOKEN_INVALID_CODE)
            self.token = phone_validation_token.uuid
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError(
                'Your code is incorrect',
                code=constants.TOKEN_INVALID_CODE)

        return attrs

    def save(self):
        pass


class BasicRegistrationSerializer(BasicSerializer):
    full_name = serializers.CharField()
    email = serializers.CharField()
    password = serializers.CharField(min_length=6)
    phone = serializers.CharField()
    token = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory
        from talos.models import OneTimePasswordCredentialDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE)
        self.request = passed_kwargs_from_view.get('request')
        self.principal = None
        self.token = None

        super(BasicRegistrationSerializer, self).__init__(*args, **kwargs)

    def validate_email(self, email):
        from talos_rest.validators import validate_email

        email = email.lower()

        validate_email(email)

        try:
            Principal.objects.get(email=email)
            raise serializers.ValidationError("Email is already used",
                                              code=constants.EMAIL_USED_CODE)
        except Principal.DoesNotExist:
            pass
        return email

    def validate_phone(self, phone):
        from talos_rest.validators import validate_phone

        validate_phone(phone)

        try:
            Principal.objects.get(phone=phone)
            raise serializers.ValidationError("Phone is already used",
                                              code=constants.PHONE_USED_CODE)
        except Principal.DoesNotExist:
            pass
        return phone

    def validate_token(self, token):
        try:
            ValidationToken.objects.get(uuid=token,
                                        is_active=True,
                                        type='principal_registration')
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError('Token does not exists',
                                              constants.TOKEN_INVALID_CODE)
        return token

    def validate_password(self, password):
        from talos_rest.validators import validate_password

        validate_password(password)

        return password

    def validate(self, attrs):

        token = attrs['token']
        phone = attrs['phone']

        try:
            self.token = ValidationToken.objects.get(identifier='phone',
                                                     identifier_value=phone,
                                                     uuid=token,
                                                     is_active=True)
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError('Token and phone is invalid',
                                              code=constants.TOKEN_INVALID_CODE)
        return attrs

    def save(self):
        self.principal = Principal()
        self.principal.email = self.validated_data['email']
        self.principal.phone = self.validated_data['phone']
        self.principal.full_name = self.validated_data['full_name']

        self.principal.save()

        self.identity_directory.create_credentials(self.principal,
                                                   {'username': self.validated_data['email']})
        self.credential_directory.create_credentials(self.principal,
                                                     {'password': self.validated_data['password']})

        if self.token:
            self.token.principal = self.principal
            self.token.is_active = False
            self.token.save()


class EmailChangeRequestSerializer(BasicSerializer):
    token_type = 'email_change'

    new_email = serializers.CharField(label='New E-mail')

    def __init__(self, *args, **kwargs):
        self.request = kwargs['context'].get('request')
        del kwargs['context']
        super(EmailChangeRequestSerializer, self).__init__(*args, **kwargs)

    def validate_new_email(self, value):
        new_email = value

        if not email_regex.match(new_email):
            raise serializers.ValidationError(
                'E-mail address is ill-formed.',
                code=constants.EMAIL_INVALID_CODE)

        try:
            Principal.objects.get(email=new_email)
            raise serializers.ValidationError(
                'Principal with provided e-mail is already registered.',
                code=constants.EMAIL_USED_CODE)
        except Principal.DoesNotExist:
            pass

        return new_email

    def save(self):

        new_email = self.validated_data['new_email']

        validation_token = ValidationToken()
        validation_token.identifier = 'email'
        validation_token.identifier_value = new_email
        validation_token.principal = self.request.principal
        validation_token.type = self.token_type
        validation_token.save()

        # TODO SEND MAIL with link


class EmailChangeValidationTokenCheckerSerializer(ValidateSecretWhenLogedInMixin, BasicSerializer):
    """
    Validate token from Email Change
    if token is valid it means that email is validated successfully
    """
    token_type = 'email_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view
        super(EmailChangeValidationTokenCheckerSerializer, self).__init__(*args, **kwargs)


class EmailChangeInsecureSerializer(SMSOtpSerializerMixin,
                                    ValidatePasswordMixin,
                                    ValidateSecretWhenLogedInMixin,
                                    BasicSerializer):
    token_type = 'email_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        super(EmailChangeInsecureSerializer, self).__init__(*args, **kwargs)

    def save(self):
        from talos.models import BasicIdentity

        self.token.principal.email = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        basic_identity = BasicIdentity.objects.get(principal=self.principal)
        basic_identity.username = self.token.identifier_value
        basic_identity.save()
        # Remove session to logout
        self.request.session.flush()

        # TODO Send link to new email
        # TODO Send sms to old phone
        # TODO Send mail to old email for 5 days


class EmailChangeSecureSerializer(GoogleOtpSerializerMixin,
                                  ValidateSecretWhenLogedInMixin,
                                  ValidatePasswordMixin,
                                  BasicSerializer):
    token_type = 'email_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        super(EmailChangeSecureSerializer, self).__init__(*args, **kwargs)

    def save(self):
        from talos.models import BasicIdentity

        self.token.principal.email = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        basic_identity = BasicIdentity.objects.get(principal=self.principal)
        basic_identity.username = self.token.identifier_value
        basic_identity.save()
        self.request.session.flush()
        # TODO Send link to new email
        # TODO Send sms to old phone
        # TODO Send mail to old email for 5 days


class EmailResetRequestSerializer(BasicSerializer):
    old_email = serializers.CharField(label='Old E-mail')
    new_email = serializers.CharField(label='New E-mail')
    token_type = 'email_reset'

    def __init__(self, *args, **kwargs):
        self.request = kwargs['context'].get('request')
        del kwargs['context']
        super(EmailResetRequestSerializer, self).__init__(*args, **kwargs)

    def validate_new_email(self, value):
        new_email = value

        if not email_regex.match(new_email):
            raise serializers.ValidationError(
                'E-mail address is ill-formed.',
                code=constants.EMAIL_INVALID_CODE)

        try:
            Principal.objects.get(email=new_email)
            raise serializers.ValidationError(
                'Principal with provided e-mail is already registered.',
                code=constants.EMAIL_USED_CODE)
        except Principal.DoesNotExist:
            pass

        return new_email

    def validate_old_email(self, email):
        if not email_regex.match(email):
            raise serializers.ValidationError(
                'E-mail address is ill-formed.',
                code=constants.EMAIL_INVALID_CODE)

        try:
            Principal.objects.get(email=email)
        except Principal.DoesNotExist:
            raise serializers.ValidationError(
                'Principal with provided email not exists',
                code=constants.EMAIL_INVALID_CODE)

        return email

    def save(self):
        new_email = self.validated_data['new_email']
        old_email = self.validated_data['old_email']

        validation_token = ValidationToken()
        validation_token.identifier = 'email'
        validation_token.identifier_value = new_email
        principal = Principal.objects.get(email=old_email)
        validation_token.principal = principal
        validation_token.type = self.token_type
        validation_token.save()


#
#  TODO SEND MAIL with link
#


class EmailResetValidationTokenCheckerSerializer(ValidateSecretWhenLoggedOutMixin, serializers.Serializer):
    token_type = 'email_reset'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view
        super(EmailResetValidationTokenCheckerSerializer, self).__init__(*args, **kwargs)


class EmailResetInsecureSerializer(SMSOtpSerializerMixin, ValidatePasswordMixin, BasicSerializer):
    token_type = 'email_reset'
    token = serializers.CharField(label='Token')

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = None

        super(EmailResetInsecureSerializer, self).__init__(*args, **kwargs)

    def validate_token(self, token):
        """ Validate token"""
        try:
            self.token = ValidationToken.objects.get(
                secret=token,
                type=self.token_type,
                expires_at__gt=_tznow(),
                is_active=True
            )

        except ValidationToken.DoesNotExist:
            self.token = None

        if not self.token:
            raise serializers.ValidationError(
                'Token is not valid.',
                code=constants.TOKEN_INVALID_CODE)
        else:
            self.principal = self.token.principal
        return self.token

    def save(self):
        from talos.models import BasicIdentity

        self.token.principal.email = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        basic_identity = BasicIdentity.objects.get(principal=self.principal)
        basic_identity.username = self.token.identifier_value
        basic_identity.save()
        # TODO Send link to new email
        # TODO Send sms to old phone
        # TODO Send mail to old email for 5 days


class EmailResetSecureSerializer(SMSOtpSerializerMixin,
                                 GoogleOtpSerializerMixin,
                                 ValidatePasswordMixin,
                                 BasicSerializer):
    token_type = 'email_reset'
    token = serializers.CharField(label='Token')

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = None

        super(EmailResetSecureSerializer, self).__init__(*args, **kwargs)

    def validate_token(self, token):
        """ Validate token"""
        try:
            self.token = ValidationToken.objects.get(
                secret=token,
                type=self.token_type,
                expires_at__gt=_tznow(),
                is_active=True)

        except ValidationToken.DoesNotExist:
            self.token = None

        if not self.token:
            raise serializers.ValidationError(
                'Token is not valid.',
                code=constants.TOKEN_INVALID_CODE)
        else:
            self.principal = self.token.principal

    def save(self):
        from talos.models import BasicIdentity

        self.token.principal.email = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        basic_identity = BasicIdentity.objects.get(principal=self.principal)
        basic_identity.username = self.token.identifier_value
        basic_identity.save()
        # TODO Send link to new email
        # TODO Send sms to old phone
        # TODO Send mail to old email for 5 days


class PhoneChangeRequestSerializer(BasicSerializer):
    token_type = 'phone_change'

    new_phone = serializers.CharField(label='New Phone')

    def __init__(self, *args, **kwargs):
        self.request = kwargs['context'].get('request')
        del kwargs['context']
        super(PhoneChangeRequestSerializer, self).__init__(*args, **kwargs)

    def validate_new_phone(self, new_phone):
        try:
            Principal.objects.get(phone=new_phone)
            raise serializers.ValidationError(
                'Principal with provided phone is already registered.',
                code=constants.PHONE_USED_CODE)
        except Principal.DoesNotExist:
            pass

        return new_phone

    def save(self):

        new_phone = self.validated_data['new_phone']

        validation_token = ValidationToken()
        validation_token.identifier = 'phone'
        validation_token.identifier_value = new_phone
        validation_token.principal = self.request.principal
        validation_token.type = self.token_type
        validation_token.save()

        # TODO SEND MAIL with link to continue phone change


class PhoneChangeValidationTokenCheckerSerializer(ValidateSecretWhenLogedInMixin, BasicSerializer):
    """
    Validate token from Phone Change
    if token is valid it means that email is validated successfully
    """
    token_type = 'phone_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view
        super(PhoneChangeValidationTokenCheckerSerializer, self).__init__(*args, **kwargs)


class PhoneChangeSecureSerializer(GoogleOtpSerializerMixin,
                                  ValidateSecretWhenLogedInMixin,
                                  ValidatePasswordMixin,
                                  BasicSerializer):
    token_type = 'phone_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        super(PhoneChangeSecureSerializer, self).__init__(*args, **kwargs)

    def save(self):
        self.token.principal.phone = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        # TODO Send sms to new phone


class PhoneChangeInsecureSerializer(SMSOtpSerializerMixin,
                                    ValidateSecretWhenLogedInMixin,
                                    ValidatePasswordMixin,
                                    BasicSerializer):
    token_type = 'phone_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        super(PhoneChangeInsecureSerializer, self).__init__(*args, **kwargs)

    def save(self):
        self.token.principal.phone = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        # TODO Send sms to new phone


class PhoneResetRequestSerializer(BasicSerializer):
    token_type = 'phone_reset'

    email = serializers.CharField(label='Email', max_length=255)
    new_phone = serializers.CharField(label='New Phone', max_length=255)

    def __init__(self, *args, **kwargs):
        self.request = kwargs['context'].get('request')
        del kwargs['context']
        super(PhoneResetRequestSerializer, self).__init__(*args, **kwargs)

    def validate_new_phone(self, new_phone):
        try:
            Principal.objects.get(phone=new_phone)
            raise serializers.ValidationError(
                'Principal with provided phone is already registered.',
                code=constants.PHONE_USED_CODE)
        except Principal.DoesNotExist:
            pass

        return new_phone

    def validate_email(self, email):
        if not email_regex.match(email):
            raise serializers.ValidationError(
                'E-mail address is ill-formed.',
                code=constants.EMAIL_INVALID_CODE)

        try:
            Principal.objects.get(email=email)
        except Principal.DoesNotExist:
            raise serializers.ValidationError(
                'Principal with provided email not exists',
                code=constants.EMAIL_INVALID_CODE)

        return email

    def save(self):
        new_phone = self.validated_data['new_phone']
        email = self.validated_data['email']

        validation_token = ValidationToken()
        validation_token.identifier = 'phone'
        validation_token.identifier_value = new_phone
        principal = Principal.objects.get(email=email)
        validation_token.principal = principal
        validation_token.type = self.token_type
        validation_token.save()

        # TODO SEND MAIL with link


class PhoneResetValidationTokenCheckerSerializer(ValidateSecretWhenLoggedOutMixin, BasicSerializer):
    token_type = 'phone_reset'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view
        super(PhoneResetValidationTokenCheckerSerializer, self).__init__(*args, **kwargs)


class PhoneResetInsecureSerializer(SMSOtpSerializerMixin, ValidatePasswordMixin, BasicSerializer):
    token_type = 'phone_reset'
    token = serializers.CharField(label='Token')

    def __init__(self, *args, **kwargs):
        self.principal = None
        super(PhoneResetInsecureSerializer, self).__init__(*args, **kwargs)

    def validate_token(self, token):
        """ Validate token"""
        try:
            self.token = ValidationToken.objects.get(
                secret=token,
                type=self.token_type,
                expires_at__gt=_tznow(),
                is_active=True
            )

        except ValidationToken.DoesNotExist:
            self.token = None

        if not self.token:
            raise serializers.ValidationError(
                'Token is not valid.',
                code=constants.TOKEN_INVALID_CODE)
        else:
            self.principal = self.token.principal

    def save(self):
        self.token.principal.phone = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        # TODO Send sms to new phone


class PhoneResetSecureSerializer(GoogleOtpSerializerMixin, ValidatePasswordMixin, BasicSerializer):
    token_type = 'phone_reset'
    token = serializers.CharField(label='Token')

    def __init__(self, *args, **kwargs):
        self.principal = None
        super(PhoneResetSecureSerializer, self).__init__(*args, **kwargs)

    def validate_token(self, token):
        """ Validate token"""
        try:
            self.token = ValidationToken.objects.get(
                secret=token,
                type=self.token_type,
                expires_at__gt=_tznow(),
                is_active=True
            )

        except ValidationToken.DoesNotExist:
            self.token = None

        if not self.token:
            raise serializers.ValidationError(
                'Token is not valid.',
                code=constants.TOKEN_INVALID_CODE)
        else:
            self.principal = self.token.principal

    def save(self):
        self.token.principal.phone = self.token.identifier_value
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        # TODO Send sms to new phone


class PasswordResetRequestSerializer(BasicSerializer):
    email = serializers.CharField()

    token_type = 'password_reset'

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)
        self.principal = None
        super(PasswordResetRequestSerializer, self).__init__(*args, **kwargs)

    def validate_email(self, email):
        try:
            principal = Principal.objects.get(email=email)
            self.principal = principal
        except Principal.DoesNotExist:
            raise serializers.ValidationError("Email doesn't exists",
                                              code=constants.EMAIL_INVALID_CODE)
        return email

    def save(self):
        validation_token = ValidationToken()
        validation_token.identifier = 'email'
        validation_token.identifier_value = self.validated_data['email']
        validation_token.principal = self.principal
        validation_token.type = self.token_type
        validation_token.save()

        # context = {
        #     'url': '{0}://{1}{2}'.format(
        #         self.request.scheme,
        #         self.request.META['HTTP_HOST'],
        #         reverse('talos-email-change-confirm-edit', args=[validation_token.secret])),
        #     'principal': validation_token.principal,
        #     'new_email': new_email}

        #
        # mail_subject = render_to_string('talos/email_change/request_email_subject.txt', context)
        # mail_body_text = render_to_string('talos/email_change/request_email_body.txt', context)
        # mail_body_html = render_to_string('talos/email_change/request_email_body.html', context)
        #
        # send_mail(
        #     subject=mail_subject,
        #     message=mail_body_text,
        #     html_message=mail_body_html,
        #     from_email=None,
        #     recipient_list=[new_email],
        #     fail_silently=True)


class PasswordResetInsecureSerializer(SMSOtpSerializerMixin, BasicSerializer):
    token = serializers.CharField()
    password = serializers.CharField()

    token_type = 'password_reset'

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import BasicIdentityDirectory

        passed_kwargs_from_view = kwargs.get('context')

        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)
        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory
        self.principal = None
        self.validation_token = None
        super(PasswordResetInsecureSerializer, self).__init__(*args, **kwargs)

    def validate_token(self, token):
        try:
            validation_token = ValidationToken.objects.get(secret=token,
                                                           is_active=True,
                                                           type=self.token_type)
            self.validation_token = validation_token
            self.principal = self.validation_token.principal
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError("Token doesn't exits",
                                              code=constants.TOKEN_INVALID_CODE)
        return token

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


class PasswordResetSecureSerializer(GoogleOtpSerializerMixin,
                                    BasicSerializer):
    password = serializers.CharField()
    token = serializers.CharField()

    token_type = 'password_reset'

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory

        passed_kwargs_from_view = kwargs.get('context')

        self.basic_identity_directory = BasicIdentityDirectory.objects.get(code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory

        self.principal = None
        self.validation_token = None
        super(PasswordResetSecureSerializer, self).__init__(*args, **kwargs)

    def validate_token(self, token):
        try:

            validation_token = ValidationToken.objects.get(secret=token,
                                                           is_active=True)
            self.validation_token = validation_token
            self.principal = self.validation_token.principal
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError("Token doesn't exits",
                                              code=constants.TOKEN_INVALID_CODE)
        return token

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


class PasswordChangeInsecureSerializer(SMSOtpSerializerMixin,
                                       ValidatePasswordMixin,
                                       BasicSerializer):
    new_password = serializers.CharField()

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal

        super(PasswordChangeInsecureSerializer, self).__init__(*args, **kwargs)

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


class PasswordChangeSecureSerializer(GoogleOtpSerializerMixin,
                                     ValidatePasswordMixin,
                                     BasicSerializer):
    new_password = serializers.CharField()

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        super(PasswordChangeSecureSerializer, self).__init__(self, *args, **kwargs)

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


class LdapLoginSerializer(BasicSerializer):
    email = serializers.CharField(label='Email', help_text='Please enter email')
    password = serializers.CharField(label='Password', help_text='Please enter password')

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.evidences = list(self.credential_directory.provided_evidences.all().order_by('id'))
        self.request = passed_kwargs_from_view['request']
        self.principal = None
        del passed_kwargs_from_view['identity_directory_code']
        del passed_kwargs_from_view['request']

        super(LdapLoginSerializer, self).__init__(*args, **kwargs)

    def validate_email(self, value):

        self.email = value

        self.principal = self.identity_directory.get_principal({'username': self.email})

        if not self.principal:
            raise serializers.ValidationError(
                'Username is not valid. Note that username may be case-sensitive.',
                code=constants.USERNAME_INVALID_CODE)

        if not self.principal.is_active:
            raise serializers.ValidationError(
                'Username is valid, but account is disabled.',
                code=constants.ACCOUNT_INACTIVE_CODE)

        return self.email

    def validate_password(self, value):
        password = value
        if self.principal and (
                not self.credential_directory.verify_credentials(self.email,
                                                                 {'password': password})):
            raise serializers.ValidationError(
                'Password is not valid. Note that password is case-sensitive.',
                code=constants.PASSWORD_INVALID_CODE)

        # return password

    def save(self):
        self.principal._load_authentication_context(self.evidences)
        self.request.principal = self.principal
