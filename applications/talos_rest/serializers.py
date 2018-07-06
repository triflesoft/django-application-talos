from re import compile
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.urls import reverse
from rest_framework import serializers
from talos.models import Principal
from talos.models import ValidationToken
from talos.models import _tznow
from rest_framework import status
from talos_rest import constants

email_regex = compile(r'^[^@]+@[^@]+\.[^@]+$')

PHONE_SMS_CREDENTIAL_DIRECTORY_CODE = 'onetimepassword_internal_phone_sms_authenticator'
GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE = 'onetimepassword_internal_google_authenticator'

class OTPBaserSerializeMixin():
    def __init__(self, *args, **kwargs):
        self.fields['otp_code'] = serializers.CharField(label='SMS Code')
        self.otp_directory = None
        super(OTPBaserSerializeMixin, self).__init__(*args, **kwargs)

    def validate_otp_code(self, otp_code):
        from talos.models import OneTimePasswordCredentialDirectory

        self.otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=self.directory_code)

        if not self.otp_directory.verify_credentials(self.principal,
                                                         {'code': otp_code}):
            raise serializers.ValidationError('OTP code is incorrect',
                                              code=self.error_code)

class SMSOtpSerializerMixin(OTPBaserSerializeMixin):
    error_code = constants.SMS_OTP_INVALID_CODE
    directory_code = PHONE_SMS_CREDENTIAL_DIRECTORY_CODE


class GoogleOtpSerializerMixin(OTPBaserSerializeMixin):
    error_code = constants.GOOGLE_OTP_INVALID_CODE
    directory_code = GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE


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


class GeneratePhoneCodeForAuthorizedUserSerializer(BasicSerializer):

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


class VerifyPhoneCodeForAuthorizedUserSerializer(BasicSerializer):
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

class AddEvidenceBaseSerialize(OTPBaserSerializeMixin, BasicSerializer):
    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal

        self.directory_code = passed_kwargs_from_view.get('directory_code', 'default_directory_code')
        self.error_code = passed_kwargs_from_view.get('error_code', 'default_error_code')


        self.otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=self.directory_code)
        self.otp_evidences = self.otp_directory.provided_evidences.all().order_by('-id')



        super(AddEvidenceBaseSerialize, self).__init__(*args, **kwargs)

    def save(self):
        from talos.models import Evidence

        evidence_codes = [evidence.code for evidence in self.otp_evidences]
        evidence_codes.extend(self.principal.get_current_evidence_code_list())
        provided_evidences = Evidence.objects.filter(code__in=evidence_codes)
        self.principal._load_authentication_context(provided_evidences)


class GeneratePhoneCodeForUnAuthorizedUserSerializer(BasicSerializer):
    phone = serializers.CharField()

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        super(GeneratePhoneCodeForUnAuthorizedUserSerializer, self).__init__(*args, **kwargs)

    def validate_phone(self, phone):
        from talos_rest.validators import validate_phone

        validate_phone(phone)

        if Principal.objects.filter(phone=phone).count() > 0:
            raise serializers.ValidationError('This mobile phone is already user',
                                              code=constants.PHONE_USED_CODE)
        return phone

    def save(self):
        from os import urandom
        from talos.contrib.sms_sender import SMSSender
        from pyotp import TOTP
        import base64

        phone = self.validated_data['phone']

        secret = urandom(64)

        self.request.session['secret'] = secret.hex()

        totp = TOTP(base64.b32encode(secret))
        sms_sender = SMSSender()

        if not sms_sender.send_message(phone, 'You registration code is {}'.format(totp.now())):
            raise serializers.ValidationError('This mobile phone is invalid',
                                              code=constants.PHONE_INVALID_CODE)


class BasicRegistrationSerializer(BasicSerializer):
    full_name = serializers.CharField()
    email = serializers.CharField()
    password = serializers.CharField(min_length=6)
    phone = serializers.CharField()
    code = serializers.CharField()

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
        self.secret = None

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

    def validate_code(self, code):
        import pyotp
        import base64

        if self.request.session.get('secret') is not None:
            self.secret = self.request.session['secret']

            totp = pyotp.TOTP(base64.b32encode(bytes.fromhex(self.secret)))

            if not totp.verify(code):
                raise serializers.ValidationError('Code is invalid',
                                                  constants.PHONE_INVALID_CODE)
            del self.request.session['secret']
        else:
            raise serializers.ValidationError('Code is invalid',
                                              constants.PHONE_INVALID_CODE)
        return code

    def validate_password(self, password):
        from talos_rest.validators import validate_password

        validate_password(password)

        return password

    def save(self):
        self.principal = Principal()
        self.principal.email = self.validated_data['email']
        self.principal.phone = self.validated_data['phone']
        self.principal.full_name = self.validated_data['full_name']
        self.principal.salt = bytes.fromhex(self.secret)
        self.principal.save()

        self.identity_directory.create_credentials(self.principal,
                                                   {'username': self.validated_data['email']})
        self.credential_directory.create_credentials(self.principal,
                                                     {'password': self.validated_data['password']})



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

        context = {
            'email' : new_email,
            'url' : 'http://localhost:8000/email-change-validation/{}'.format(validation_token.secret)

        }

        mail_subject = render_to_string('talos/email_change/request_email_subject.txt', context)
        mail_body_text = render_to_string('talos/email_change/request_email_body.txt', context)
        mail_body_html = render_to_string('talos/email_change/request_email_body.html', context)

        send_mail(
            subject=mail_subject,
            message=mail_body_text,
            html_message=mail_body_html,
            from_email=None,
            recipient_list=[new_email],
            fail_silently=True
        )



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


class EmailChangeBaseSerialize(OTPBaserSerializeMixin,
                               ValidatePasswordMixin,
                               ValidateSecretWhenLogedInMixin,
                               BasicSerializer):
    token_type = 'email_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal

        self.directory_code = passed_kwargs_from_view.get('directory_code', 'default_directory_code')
        self.error_code = passed_kwargs_from_view.get('error_code', 'default_error_code')

        super(EmailChangeBaseSerialize, self).__init__(*args, **kwargs)

    def save(self):
        from talos.models import BasicIdentity
        from talos.contrib.sms_sender import SMSSender

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

        mail_subject = render_to_string('talos/email_change/confirmed_email_subject.txt', context)
        mail_body_text = render_to_string('talos/email_change/confirmed_email_body.txt', context)
        mail_body_html = render_to_string('talos/email_change/confirmed_email_body.html', context)

        send_mail(
            subject=mail_subject,
            message=mail_body_text,
            html_message=mail_body_html,
            from_email=None,
            recipient_list=[self.token.principal.email, old_email],
            fail_silently=True
        )

        mail_change_text = render_to_string('talos/email_change/confirmed_email_body_mobile.txt')
        sms_sender = SMSSender()
        sms_sender.send_message(self.token.principal.phone, mail_change_text)


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

        mail_subject = render_to_string('talos/email_reset/request_email_reset_subject.txt', context)
        mail_body_text = render_to_string('talos/email_reset/request_email_reset_body.txt', context)
        mail_body_html = render_to_string('talos/email_reset/request_email_reset_body.html', context)

        send_mail(
            subject=mail_subject,
            message=mail_body_text,
            html_message=mail_body_html,
            from_email=None,
            recipient_list=[self.token.principal.email],
            fail_silently=True
        )




class EmailResetValidationTokenCheckerSerializer(ValidateSecretWhenLoggedOutMixin, serializers.Serializer):
    token_type = 'email_reset'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view
        super(EmailResetValidationTokenCheckerSerializer, self).__init__(*args, **kwargs)


class EmailResetBaseSerializer(BasicSerializer):
    token_type = 'email_reset'
    token = serializers.CharField(label='Token')

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = None

        self.directory_code = passed_kwargs_from_view.get('directory_code', 'default_directory_code')
        self.error_code = passed_kwargs_from_view.get('error_code', 'default_error_code')

        super(EmailResetBaseSerializer, self).__init__(*args, **kwargs)

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
        from talos.contrib.sms_sender import SMSSender

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

        mail_subject = render_to_string('talos/email_reset/confirmed_email_reset_subject.txt', context)
        mail_body_text = render_to_string('talos/email_reset/confirmed_email_reset_body.txt', context)
        mail_body_html = render_to_string('talos/email_reset/confirmed_email_reset_body.html', context)

        send_mail(
            subject=mail_subject,
            message=mail_body_text,
            html_message=mail_body_html,
            from_email=None,
            recipient_list=[self.token.principal.email],
            fail_silently=True
        )

        phone_text = render_to_string('talos/email_reset/confirmed_email_reset_mobile.txt')
        sms_sender = SMSSender()
        sms_sender.send_message(self.token.principal.phone, phone_text)


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

        url = '{0}://{1}{2}'.format(
            self.request.scheme,
            self.request.META.get('HTTP_HOST', 'test_host'),
            reverse('phone-change-token-validation', args=[validation_token.secret])
        )

        context = {
            'email': self.principal.email,
            'url': url

        }

        mail_subject = render_to_string('talos/phone_change/request_phone_subject.txt', context)
        mail_body_text = render_to_string('talos/phone_change/request_phone_body.txt', context)
        mail_body_html = render_to_string('talos/phone_change/request_phone_body.html', context)

        send_mail(
            subject=mail_subject,
            message=mail_body_text,
            html_message=mail_body_html,
            from_email=None,
            recipient_list=[self.token.principal.email],
            fail_silently=True
        )


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


class PhoneChangeBaseSerialize(BasicSerializer):
    token_type = 'phone_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal

        self.directory_code = passed_kwargs_from_view.get('directory_code', 'default_directory_code')
        self.error_code = passed_kwargs_from_view.get('error_code', 'default_error_code')

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

        url = '{0}://{1}{2}'.format(
            self.request.scheme,
            self.request.META.get('HTTP_HOST', 'test_host'),
            reverse('phone-reset-token-validation', args=[validation_token.secret])
        )

        context = {
            'email': self.principal.email,
            'url': url
        }

        mail_subject = render_to_string('talos/phone_reset/request_phone_reset_subject.txt', context)
        mail_body_text = render_to_string('talos/phone_reset/request_phone_reset_body.txt', context)
        mail_body_html = render_to_string('talos/phone_reset/request_phone_reset_body.html', context)

        send_mail(
            subject=mail_subject,
            message=mail_body_text,
            html_message=mail_body_html,
            from_email=None,
            recipient_list=[self.token.principal.email],
            fail_silently=True
        )


class PhoneResetValidationTokenCheckerSerializer(ValidateSecretWhenLoggedOutMixin, BasicSerializer):
    token_type = 'phone_reset'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view
        super(PhoneResetValidationTokenCheckerSerializer, self).__init__(*args, **kwargs)


class PhoneResetBaseSerialize(OTPBaserSerializeMixin, ValidatePasswordMixin, BasicSerializer):
    token_type = 'phone_reset'
    token = serializers.CharField(label='Token')

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')

        self.directory_code = kwargs.get('directory_code', 'default_directory_code')
        self.error_code = kwargs.get('error_code', 'default_error_code')

        self.principal = None
        super(PhoneResetBaseSerialize, self).__init__(*args, **kwargs)

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
        email = self.validated_data['email']

        validation_token = ValidationToken()
        validation_token.identifier = 'email'
        validation_token.identifier_value = email
        validation_token.principal = self.principal
        validation_token.type = self.token_type
        validation_token.save()

        url = '{0}://{1}{2}'.format(
            self.request.scheme,
            self.request.META.get('HTTP_HOST', 'test_host'),
            reverse('password-reset-validation', args=[self.token.secret])
        )


        context = {
            'email': email,
            'url': url,
            'recipient_name': validation_token.principal.full_name,
        }


        mail_subject = render_to_string('talos/email_change/request_email_subject.txt', context)
        mail_body_text = render_to_string('talos/email_change/request_email_body.txt', context)
        mail_body_html = render_to_string('talos/email_change/request_email_body.html', context)

        send_mail(
            subject=mail_subject,
            message=mail_body_text,
            html_message=mail_body_html,
            from_email=None,
            recipient_list=[email],
            fail_silently=True)



class PasswordResetValidationTokenSerializer(ValidateSecretWhenLoggedOutMixin,
                                            BasicSerializer):
    token_type = 'password_reset'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        super(PasswordResetValidationTokenSerializer, self).__init__(*args, **kwargs)


class PasswordResetBaseSerializer(OTPBaserSerializeMixin, BasicSerializer):
    token = serializers.CharField()
    password = serializers.CharField()

    token_type = 'password_reset'

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory

        passed_kwargs_from_view = kwargs.get('context')

        self.directory_code = passed_kwargs_from_view.get('directory_code', 'default_directory_code')
        self.error_code = passed_kwargs_from_view.get('error_code', 'default_error_code')

        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory

        self.principal = None
        self.validation_token = None
        super(PasswordResetBaseSerializer, self).__init__(*args, **kwargs)

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


class PasswordChangeBaseSerialize(OTPBaserSerializeMixin, ValidatePasswordMixin, BasicSerializer):
    new_password = serializers.CharField()

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal

        self.directory_code = passed_kwargs_from_view.get('directory_code', 'default_directory_code')
        self.error_code = passed_kwargs_from_view.get('error_code', 'default_error_code')

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
