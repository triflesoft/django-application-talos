from django.core.exceptions import ValidationError
from django.urls import reverse
from rest_framework import serializers
from re import compile
from talos.models import Principal, ValidationToken, _tznow
from rest_framework import status

email_regex = compile(r'^[^@]+@[^@]+\.[^@]+$')


class BasicSerializer(serializers.Serializer):
    BASIC_SUCCESS_CODE = status.HTTP_200_OK

    def to_representation(self, instance):
        data = super(BasicSerializer, self).to_representation(instance)
        final_data = {'status': self.BASIC_SUCCESS_CODE,
                      'result': data}
        return final_data


class SessionSerializer(BasicSerializer):
    username = serializers.CharField(label='Username', help_text='Please enter username')
    password = serializers.CharField(label='Password', help_text='Please enter password')

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.evidences = list(self.credential_directory.provided_evidences.all().order_by('id'))
        self.request = passed_kwargs_from_view['request']

        del passed_kwargs_from_view['identity_directory_code']
        del passed_kwargs_from_view['request']

        super(SessionSerializer, self).__init__(*args, **kwargs)

    def validate_username(self, value):

        username = value

        self.principal = self.identity_directory.get_principal({'username': username})

        if not self.principal:
            raise serializers.ValidationError(
                'Username is not valid. Note that username may be case-sensitive.',
                code='invalid_username')

        if not self.principal.is_active:
            raise serializers.ValidationError(
                'Username is valid, but account is disabled.',
                code='invalid_username')

        return username

    def validate_password(self, value):
        password = value
        if self.principal and (
                not self.credential_directory.verify_credentials(self.principal,
                                                                 {'password': password})):
            raise serializers.ValidationError(
                'Password is not valid. Note that password is case-sensitive.',
                code='invalid_password')

        # return password

    def save(self):
        self.principal._load_authentication_context(self.evidences)
        self.request.principal = self.principal


class PrincipalRegistrationRequestSerializer(BasicSerializer):
    email = serializers.CharField(label='E-mail')

    def __init__(self, *args, **kwargs):
        self.request = kwargs['context'].get('request')

        super(PrincipalRegistrationRequestSerializer, self).__init__(*args, **kwargs)

    def validate_email(self, value):
        email = value

        if not email_regex.match(email):
            raise serializers.ValidationError('E-mail address is ill-formed',
                                              code='invalid_email')

        try:
            principal = Principal.objects.get(email=email)

            raise serializers.ValidationError(
                'Principal with provided e-mail is already registered',
                code='email_exists')
        except Principal.DoesNotExist:
            pass
        return email

    def save(self):
        # TODO send mail
        from django.core.mail import send_mail
        from django.template.loader import render_to_string
        from django.urls import reverse
        from talos.models import ValidationToken

        email = self.validated_data['email']

        validation_token = ValidationToken()
        validation_token.email = email
        validation_token.type = 'principal_registration'
        validation_token.save()
        self.validation_token = validation_token
        # context = {
        #     'url': '{0}://{1}{2}'.format(
        #         self.request.scheme,
        #         self.request.META['HTTP_HOST'],
        #         reverse('talos-principal-registration-confirm-edit',
        #                 args=[validation_token.secret])),
        #     'email': email}
        # mail_subject = render_to_string('talos/basic_password_reset/request_email_subject.txt', context)
        # mail_body_text = render_to_string('talos/basic_password_reset/request_email_body.txt', context)
        # mail_body_html = render_to_string('talos/basic_password_reset/request_email_body.html', context)
        # email = self.validated_data['email']
        # send_mail(
        #     subject=mail_subject,
        #     message=mail_body_text,
        #     html_message=mail_body_html,
        #     from_email=None,
        #     recipient_list=[email],
        #     fail_silently=True)


class PrincipalRegistrationTokenValidationSerializer(BasicSerializer):
    """ Validate token from PrincipalRegistrationRequest
        if token is valid it means that email is validated successfully
    """
    secret = serializers.CharField(label='Token', max_length=255)

    def __init__(self, *args, **kwargs):
        super(PrincipalRegistrationTokenValidationSerializer, self).__init__(*args, **kwargs)

    def validate_secret(self, value):
        """ Validate token"""
        try:
            token = ValidationToken.objects.get(
                secret=value,
                type='principal_registration',
                expires_at__gt=_tznow(),
            )

        except ValidationToken.DoesNotExist:
            token = None
        if not token:
            raise serializers.ValidationError("Token don't exists",
                                              code="token_not_found")
        # If token is not active it means that it was already used(Email verification is passed)
        if not token.is_active:
            raise serializers.ValidationError("Token already used", code='token_already_exist')
        return token


class PrincipalRegistrationConfirmSerializer(BasicSerializer):
    brief_name = serializers.CharField(label='Brief Name', max_length=255)
    full_name = serializers.CharField(label='Full Name', max_length=255)
    username = serializers.CharField(label='username', max_length=255)
    password1 = serializers.CharField(label='Password')
    password2 = serializers.CharField(label='Password Confirmation')

    def __init__(self, *args, **kwargs):

        from talos.models import BasicIdentityDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.request = passed_kwargs_from_view.get('request')
        self.token = passed_kwargs_from_view.get('token')
        self.principal = None

        del kwargs['context']['token']
        del kwargs['context']['identity_directory_code']
        del kwargs['context']['request']

        super(PrincipalRegistrationConfirmSerializer, self).__init__(*args, **kwargs)

    def validate_username(self, value):
        username = value

        if self.identity_directory.get_principal({'username': username}):
            raise serializers.ValidationError('Username is already taken',
                                              code='invalid_username')

        return username

    def validate_password1(self, value):

        self.password1 = value

    def validate_password2(self, value):
        password1 = self.password1
        password2 = value  # self.validated_data.get('password2', None)

        if password1 and password2 and (password1 != password2):
            raise serializers.ValidationError('Passwords do not match.',
                                              code='invalid_password_confirmation')

    def validate(self, attrs):
        if not self.token:
            raise serializers.ValidationError('Token is not valid.',
                                              code='invalid_token')

        return attrs

    def save(self):
        from django.contrib.auth.password_validation import validate_password

        username = self.validated_data['username']
        password = self.password1

        password1 = self.password1
        brief_name = self.validated_data.get('brief_name', None)
        full_name = self.validated_data.get('full_name', None)

        self.principal = Principal()
        self.principal.brief_name = brief_name
        self.principal.full_name = full_name
        self.principal.email = self.token.email

        errors = dict()
        try:
            validate_password(password1, self.principal)
        except ValidationError as e:
            errors['password'] = list(e.messages)

        if errors:
            raise serializers.ValidationError(errors)

        self.principal.save()
        self.identity_directory.create_credentials(self.principal, {'username': username})
        self.credential_directory.create_credentials(self.principal, {'password': password})
        self.token.principal = self.principal
        self.token.is_active = False
        self.token.save()





class EmailChangeConfirmSerializer(BasicSerializer):
    new_email = serializers.CharField(
        label='New E-mail',
        max_length=255)

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory
        passed_kwargs_from_view = kwargs['context']
        self.request = passed_kwargs_from_view['request']
        self.token = passed_kwargs_from_view['token']

        del kwargs['context']

        super(EmailChangeConfirmSerializer, self).__init__(*args, **kwargs)

    def validate(self, attrs):
        if not self.token or (self.token.principal != self.request.principal):
            raise serializers.ValidationError(
                'Token is not valid.',
                code='invalid_secret')

        return self.token

    def save(self):
        self.token.principal.email = self.token.email
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()


class GoogleAuthenticatorActivateRequestSerializer(serializers.Serializer):

    password = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import BasicIdentityDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        self.salt = None
        super(GoogleAuthenticatorActivateRequestSerializer, self).__init__(*args, **kwargs)

    def validate_password(self, password):
        if self.basic_credential_directory and not self.basic_credential_directory.verify_credentials(self.principal,
                                                                                                      {'password' : password}):
            raise serializers.ValidationError('Password is incorrect')
        return password

    def validate(self, attrs):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import OneTimePasswordCredential
        try:
            google_otp = self.otp_credential_directory.credentials.get(principal=self.principal)
            if google_otp.is_activated is False:
                raise serializers.ValidationError('User has turned on google-authentictor '
                                                  'but did not activated')
            else:
                raise serializers.ValidationError('User has already activated Google authenticator')
        except OneTimePasswordCredential.DoesNotExist:
            pass
        return attrs

    def save(self):
        import pyotp
        self.request.session['temp_otp_secret_key'] = pyotp.random_base32()
        self.request.session['secret_key_activated'] = True
        # Create otp_credential for user
        #if self.otp_credential_directory:
        #    salt = self.otp_credential_directory.create_credentials(self.principal, {})
        #    self.salt = salt
        self.salt = self.request.session['temp_otp_secret_key']



class GoogleAuthenticatorActivateConfirmSerializer(serializers.Serializer):
    code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        self.salt = None
        super(GoogleAuthenticatorActivateConfirmSerializer, self).__init__(*args, **kwargs)

    def validate_code(self, code):
        import pyotp

        if not self.request.session.get('secret_key_activated', False):
            raise serializers.ValidationError('You did not activated google authenticator')

        totp = pyotp.TOTP(self.request.session['temp_otp_secret_key'])
        if not totp.verify(code):
            raise serializers.ValidationError('Code is incorrect')
        return code

    def validate(self, attrs):
        return attrs

    def save(self):
        if self.otp_credential_directory:
            salt = self.otp_credential_directory.create_credentials(self.principal,
                                                                         {'salt' : self.request.session['temp_otp_secret_key']})
            self.salt = self.request.session['temp_otp_secret_key']

class GoogleAuthenticatorVerifySerializer(serializers.Serializer):
    code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        self.otp_evidences = self.otp_credential_directory.provided_evidences.all().order_by('id')
        super(GoogleAuthenticatorVerifySerializer, self).__init__(*args, **kwargs)

    def validate_code(self, value):
        if self.otp_credential_directory and not self.otp_credential_directory.verify_credentials(
                self.principal,
                {'code': value}):
            raise serializers.ValidationError('Code is incorrect')
        return value

    def save(self):
        for otp_evidence in self.otp_evidences:
            self.principal._evidences_effective[otp_evidence.code] = otp_evidence


class GoogleAuthenticatorDeleteRequestSerializer(serializers.Serializer):

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        super(GoogleAuthenticatorDeleteRequestSerializer, self).__init__(*args, **kwargs)

    def validate(self, attrs):
        return attrs

    def save(self):
        from talos.models import ValidationToken

        validation_token = ValidationToken()
        validation_token.email = self.principal.email
        validation_token.principal = self.principal
        validation_token.type = 'otp_delete'
        validation_token.save()




class GoogleAuthenticatorDeleteSerializer(serializers.Serializer):
    token = serializers.CharField()
    sms_code = serializers.CharField()
    otp_code = serializers.CharField()
    password = serializers.CharField()

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
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        self.sms_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=2)
        super(GoogleAuthenticatorDeleteSerializer, self).__init__(*args, **kwargs)



    def validate_otp_code(self, code):
        if self.otp_credential_directory and not self.otp_credential_directory.verify_credentials(self.principal,
                                                                                                  {'code': code}):

            raise serializers.ValidationError('Your code is incorrect')
        return code

    def validate_sms_code(self, sms_code):
        if self.sms_credential_directory and not self.sms_credential_directory.verify_credentials(self.principal,
                                                                                                  {'code' : sms_code}):
            raise serializers.ValidationError('Your code is incorrect')
        return sms_code

    def validate_password(self, password):
        if self.basic_credential_directory and not self.basic_credential_directory.verify_credentials(self.principal,
                                                                                                      {'password' : password}):
            raise serializers.ValidationError('Your code is incorrect')
        return password

    def validate_token(self, token):
        from talos.models import ValidationToken
        try:
            self.validation_token = ValidationToken.objects.get(email=self.principal.email,
                                                                secret=token,
                                                                is_active=True)
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError('Your token is invalid')
        return

    def delete(self):
        if self.otp_credential_directory:
            self.otp_credential_directory.reset_credentials(self.principal,
                                                            self.principal,
                                                            {})
        self.validation_token.is_active = False
        self.validation_token.save()


class GoogleAuthenticatorChangeRequestSerializer(serializers.Serializer):

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        super(GoogleAuthenticatorChangeRequestSerializer, self).__init__(*args, **kwargs)

    def validate(self, attrs):
        return attrs

    def save(self):
        validation_token = ValidationToken()
        validation_token.principal = self.principal
        validation_token.email = self.principal.email
        validation_token.type = 'otp_change'
        validation_token.save()


class GoogleAuthenticatorChangeConfirmSerializer(serializers.Serializer):
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
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        self.sms_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=2)
        super(GoogleAuthenticatorChangeConfirmSerializer, self).__init__(*args, **kwargs)


    def validate_token(self, token):
        try:
            token = ValidationToken.objects.get(secret=token,
                                                is_active=True,
                                                email=self.principal.email)
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError('Token is incorrect')
        return token

    def validate_password(self, password):
        if self.basic_credential_directory and not self.basic_credential_directory.verify_credentials(self.principal,
                                                                                                      {'password' : password}):
            raise serializers.ValidationError('Password is incorrect')
        return password

    def validate_otp_code(self, otp_code):
        if self.otp_credential_directory and not self.otp_credential_directory.verify_credentials(self.principal,
                                                                                                  {'code' : otp_code}):
            raise serializers.ValidationError('OTP Code is incorrect')
        return otp_code

    def validate_sms_code(self, sms_code):
        if self.sms_credential_directory and not self.sms_credential_directory.verify_credentials(self.principal,
                                                                                                  {'code' : sms_code}):
            raise serializers.ValidationError('SMS code is incorrect')
        return sms_code

    def save(self):
        import pyotp
        self.request.session['otp_verified'] = True
        self.request.session['temp_otp_token'] = pyotp.random_base32()
        self.salt = self.request.session['temp_otp_token']



class GoogleAuthenticatorChangeDoneSerializer(serializers.Serializer):
    otp_code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        self.sms_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=2)
        super(GoogleAuthenticatorChangeDoneSerializer, self).__init__(*args, **kwargs)


    def validate_otp_code(self, otp_code):
        import pyotp
        if not self.request.session.get('otp_verified', None) or not self.request.session.get('temp_otp_token', None):
            raise serializers.ValidationError('OTP credentials is not verified')

        print(self.request.session.get('temp_otp_token'))
        totp = pyotp.TOTP(self.request.session.get('temp_otp_token', None))
        if not totp.verify(otp_code):
            raise serializers.ValidationError('OTP Code is incorrect')
        return otp_code

    def validate(self, attrs):
        return attrs

    def save(self):
        if self.otp_credential_directory:
            self.otp_credential_directory.update_credentials(self.principal,
                                                             old_credentials=None,
                                                             new_credentials={'salt' : self.request.session['temp_otp_token']})




class GeneratePhoneCodeForAuthorizedUserSerializer(serializers.Serializer):

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(pk=2)
        super(GeneratePhoneCodeForAuthorizedUserSerializer, self).__init__(*args, **kwargs)

    def validate(self, attrs):
        return attrs

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
        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(pk=2)
        self.sms_otp_evidences = self.sms_otp_directory.provided_evidences.all().order_by('-id')
        super(VerifyPhoneCodeForAuthorizedUserSerializer, self).__init__(*args, **kwargs)

    def validate_code(self, code):
        if self.sms_otp_directory and not self.sms_otp_directory.verify_credentials(self.principal,
                                                                                    {'code': code}):
            raise serializers.ValidationError('Code is incorrect')
        return code

    def validate(self, attrs):
        return attrs

    def save(self):
        for sms_otp_evidence in self.sms_otp_evidences:
            self.principal._evidences_effective[sms_otp_evidence.code] = sms_otp_evidence


class ChangePasswordInsecureSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()
    sms_code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import BasicIdentityDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(pk=2)
        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory
        super(ChangePasswordInsecureSerializer, self).__init__(*args, **kwargs)

    def validate_full_name(self, full_name):
        return full_name

    def validate_sms_code(self, sms_code):
        if not self.sms_otp_directory.verify_credentials(self.principal,
                                                         {'code': sms_code}):
            raise serializers.ValidationError('Sms Code is incorrect')
        return sms_code

    def validate_old_password(self, old_password):
        if not self.basic_credential_directory.verify_credentials(self.principal,
                                                                  {'password': old_password}):
            raise serializers.ValidationError('Password is incorrect')
        return old_password

    def validate(self, attrs):
        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError('Passwords must be different')
        return attrs

    def save(self):
        old_credentials = {'password': self.validated_data['old_password']}
        new_credentials = {'password': self.validated_data['new_password']}
        self.basic_credential_directory.update_credentials(self.principal,
                                                           old_credentials=old_credentials,
                                                           new_credentials=new_credentials)


class ChangePasswordSecureSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()
    otp_code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import BasicIdentityDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory
        super(ChangePasswordSecureSerializer, self).__init__(*args, **kwargs)

    def validate_old_password(self, old_password):
        if not self.basic_credential_directory.verify_credentials(self.principal,
                                                                  {'password': old_password}):
            raise serializers.ValidationError('Password is incorrect')
        return old_password

    def validate(self, attrs):
        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError('Passwords must be different')
        return attrs

    def validate_otp_code(self, otp_code):
        if not self.otp_directory.verify_credentials(self.principal,
                                                     {'code': otp_code}):
            raise serializers.ValidationError('Sms Code is incorrect')
        return otp_code

    def save(self):
        old_credentials = {'password': self.validated_data['old_password']}
        new_credentials = {'password': self.validated_data['new_password']}
        self.basic_credential_directory.update_credentials(self.principal,
                                                           old_credentials=old_credentials,
                                                           new_credentials=new_credentials)


class AuthorizationUsingSMSSerializer(serializers.Serializer):
    code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(pk=2)
        self.sms_otp_evidences = self.sms_otp_directory.provided_evidences.all().order_by('-id')
        super(AuthorizationUsingSMSSerializer, self).__init__(*args, **kwargs)

    def validate_code(self, code):
        if not self.sms_otp_directory.verify_credentials(self.principal,
                                                         {'code': code}):
            raise serializers.ValidationError('Code is incorrect')
        return code

    def save(self):
        for sms_otp_evidence in self.sms_otp_evidences:
            self.principal._evidences_effective[sms_otp_evidence.code] = sms_otp_evidence


class AuthorizationUsingGoogleAuthenticatorSerializer(serializers.Serializer):
    code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        self.otp_evidences = self.otp_credential_directory.provided_evidences.all().order_by('id')
        super(AuthorizationUsingGoogleAuthenticatorSerializer, self).__init__(*args, **kwargs)

    def validate_code(self, value):
        if self.otp_credential_directory and not self.otp_credential_directory.verify_credentials(
                self.principal,
                {'code': value}):
            raise serializers.ValidationError('Code is incorrect')
        return value

    def save(self):
        for otp_evidence in self.otp_evidences:
            self.principal._evidences_effective[otp_evidence.code] = otp_evidence


class GeneratePhoneCodeForUnAuthorizedUserSerializer(serializers.Serializer):
    phone = serializers.CharField()

    def __init__(self, *args, **kwargs):
        super(GeneratePhoneCodeForUnAuthorizedUserSerializer, self).__init__(*args, **kwargs)

    def validate_phone(self, phone):
        if Principal.objects.filter(phone=phone).count() > 0:
            raise serializers.ValidationError('This mobile phone is already user')
        return phone

    def save(self):
        from talos.models import PhoneSMSValidationToken

        phone = self.validated_data['phone']

        phone_validation_token = PhoneSMSValidationToken()
        phone_validation_token.phone = phone
        phone_validation_token.save()


class VerifyPhoneCodeForUnAuthorizedUserSerializer(serializers.Serializer):
    phone = serializers.CharField()
    code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        super(VerifyPhoneCodeForUnAuthorizedUserSerializer, self).__init__(*args, **kwargs)

    def validate(self, attrs):

        from talos.models import PhoneSMSValidationToken
        phone = attrs['phone']
        code = attrs['code']

        try:
            phone_validation_token = PhoneSMSValidationToken.objects.get(phone=phone,
                                                                         is_active=True,
                                                                         salt=code.encode())
            self.secret = phone_validation_token.secret
        except PhoneSMSValidationToken.DoesNotExist:
            raise serializers.ValidationError('Your code is incorrect')
        return attrs

    def save(self):
        pass


class BasicRegistrationSerializer(serializers.Serializer):
    full_name = serializers.CharField()
    email = serializers.CharField()
    password = serializers.CharField()
    phone = serializers.CharField()
    token = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory
        from talos.models import OneTimePasswordCredentialDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=2)
        self.request = passed_kwargs_from_view.get('request')
        self.principal = None
        self.token = None

        super(BasicRegistrationSerializer, self).__init__(*args, **kwargs)

    def validate_email(self, email):
        try:
            Principal.objects.get(email=email)
            raise serializers.ValidationError("Email is already used")
        except Principal.DoesNotExist:
            pass
        return email

    def validate_phone(self, phone):
        try:
            Principal.objects.get(phone=phone)
            raise serializers.ValidationError("Phone is already used")
        except Principal.DoesNotExist:
            pass
        return phone

    def validate_token(self, token):
        from talos.models import PhoneSMSValidationToken
        try:
            PhoneSMSValidationToken.objects.get(secret=token)
        except PhoneSMSValidationToken.DoesNotExist:
            raise serializers.ValidationError("Token doesn't exists")
        return token

    def validate(self, attrs):
        from talos.models import PhoneSMSValidationToken

        token = attrs['token']
        phone = attrs['phone']

        try:
            self.token = PhoneSMSValidationToken.objects.get(phone=phone,
                                                             secret=token,
                                                             is_active=True)
        except PhoneSMSValidationToken.DoesNotExist:
            raise serializers.ValidationError("Token and phone is invalid")
        return attrs

    def save(self):
        from talos.models import PrincipalProfile

        self.principal = Principal()
        self.principal.email = self.validated_data['email']
        self.principal.phone = self.validated_data['phone']
        self.principal.full_name = self.validated_data['full_name']

        self.principal.save()


        PrincipalProfile.objects.create(principal=self.principal)


        self.identity_directory.create_credentials(self.principal, {'username': self.validated_data['email']})
        self.credential_directory.create_credentials(self.principal, {'password': self.validated_data['password']})

        # self.otp_credential_directory.create_credentials(self.principal, {})
        if self.token:
            self.token.principal = self.principal
            self.token.is_active = False
            self.token.save()

class SMSOtpSerializerMixin():

    def __init__(self, *args, **kwargs):
        self.fields['sms_code'] = serializers.CharField(label='SMS Code')
        super(SMSOtpSerializerMixin, self).__init__(*args, **kwargs)

    def validate_sms_code(self, sms_code):
        from talos.models import OneTimePasswordCredentialDirectory

        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(pk=2)

        if not self.sms_otp_directory.verify_credentials(self.principal,
                                                     {'code': sms_code}):
            raise serializers.ValidationError('OTP code is incorrect')

class GoogleOtpSerializerMixin():
    def __init__(self, *args, **kwargs):
        self.fields['otp_code']  = serializers.CharField(label='Google OTP Code', max_length=255)
        super(GoogleOtpSerializerMixin, self).__init__(*args, **kwargs)


    def validate_google_otp_code(self, google_otp_code):
        from talos.models import OneTimePasswordCredentialDirectory
        self.otp_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        if not self.otp_directory.verify_credentials(self.principal,
                                                     {'code': google_otp_code}):
            raise serializers.ValidationError('OTP code is incorrect')

class ValidatePasswordMixin():

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory
        self.fields['password'] = serializers.CharField(label='Password', max_length=255)
        passed_kwargs_from_view = kwargs.get('context')
        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory

        super(ValidatePasswordMixin, self).__init__(*args, **kwargs)

    def validate_password(self, password):
        if not self.basic_credential_directory.verify_credentials(self.principal,
                                                                  {'password': password}):
            raise serializers.ValidationError('Password is incorrect')

class ValidateSecretWhenLogedInMixin():
    def __init__(self, *args, **kwargs):
        self.fields['secret']  = serializers.CharField(label='Token', max_length=255)
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
                code='invalid_secret')

        return self.token

class ValidateSecretWhenLoggedOutMixin():
    def __init__(self, *args, **kwargs):
        self.fields['secret']  = serializers.CharField(label='Token', max_length=255)
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
                code='invalid_secret')

        return self.token


class EmailChangeRequestSerializer(BasicSerializer):
    token_type = 'email_change'

    new_email = serializers.CharField(label='New E-mail')

    def __init__(self, *args, **kwargs):
        self.request = kwargs['context'].get('request')
        del kwargs['context']
        super(EmailChangeRequestSerializer, self).__init__(*args, **kwargs)

    def validate_new_email(self, value):
        from talos.models import Principal

        new_email = value

        if not email_regex.match(new_email):
            raise serializers.ValidationError(
                'E-mail address is ill-formed.',
                code='invalid_email')

        try:
            principal = Principal.objects.get(email=new_email)

            raise serializers.ValidationError(
                'Principal with provided e-mail is already registered.',
                code='email_already_exists')
        except Principal.DoesNotExist:
            pass

        return new_email

    def save(self):

        new_email = self.validated_data['new_email']

        validation_token = ValidationToken()
        validation_token.email = new_email
        validation_token.principal = self.request.principal
        validation_token.type = self.token_type
        validation_token.save()


        # TODO SEND MAIL with link


class EmailChangeValidationTokenCheckerSerializer(ValidateSecretWhenLogedInMixin,BasicSerializer):
    """
    Validate token from Email Change
    if token is valid it means that email is validated successfully
    """
    token_type = 'email_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view
        super(EmailChangeValidationTokenCheckerSerializer, self).__init__(*args, **kwargs)


class EmailChangeInsecureSerializer(SMSOtpSerializerMixin, ValidatePasswordMixin, ValidateSecretWhenLogedInMixin, BasicSerializer):
    token_type = 'email_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        super(EmailChangeInsecureSerializer, self).__init__(*args, **kwargs)

    def save(self, **kwargs):
        from talos.models import BasicIdentity
        self.token.principal.email = self.token.email
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        basic_credential = BasicIdentity.objects.get(
            principal=self.principal
        )
        basic_credential.email = self.token.email
        basic_credential.save()
        # TODO Send link to new email
        # TODO Send sms to old phone
        # TODO Send mail to old email for 5 days


class EmailChangeSecureSerializer(SMSOtpSerializerMixin, GoogleOtpSerializerMixin, ValidateSecretWhenLogedInMixin, ValidatePasswordMixin, BasicSerializer):
    token_type = 'email_change'

    def __init__(self, *args, **kwargs):
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        super(EmailChangeSecureSerializer, self).__init__(*args, **kwargs)

    def save(self, **kwargs):
        from talos.models import BasicIdentity
        self.token.principal.email = self.token.email
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        basic_credential = BasicIdentity.objects.get(
            principal=self.principal
        )
        basic_credential.email = self.token.email
        basic_credential.save()
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
        from talos.models import Principal

        new_email = value

        if not email_regex.match(new_email):
            raise serializers.ValidationError(
                'E-mail address is ill-formed.',
                code='invalid_email')

        try:
            principal = Principal.objects.get(email=new_email)

            raise serializers.ValidationError(
                'Principal with provided e-mail is already registered.',
                code='email_already_exists')
        except Principal.DoesNotExist:
            pass

        return new_email

    def validate_old_email(self, email):
        from talos.models import Principal


        if not email_regex.match(email):
            raise serializers.ValidationError(
                'E-mail address is ill-formed.',
                code='invalid_email')

        try:
            principal = Principal.objects.get(email=email)
        except Principal.DoesNotExist:
            raise serializers.ValidationError(
                'Principal with provided email not exists',
                code='email_not_exists')

        return email

    def save(self):
        from talos.models import Principal

        new_email = self.validated_data['new_email']
        old_email = self.validated_data['old_email']

        validation_token = ValidationToken()
        validation_token.email = new_email
        principal  = Principal.objects.get(email=old_email)
        validation_token.principal = principal
        validation_token.type = self.token_type
        validation_token.save()
#
#  TODO SEND MAIL with link
#


class EmailResetValidationTokenCheckerSerializer(ValidateSecretWhenLoggedOutMixin,serializers.Serializer):
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
                code='invalid_secret')
        else:
            self.principal = self.token.principal
        return self.token


    def save(self, **kwargs):
        from talos.models import BasicIdentity
        self.token.principal.email = self.token.email
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        basic_credential = BasicIdentity.objects.get(
            principal=self.principal
        )
        basic_credential.email = self.token.email
        basic_credential.save()
        # TODO Send link to new email
        # TODO Send sms to old phone
        # TODO Send mail to old email for 5 days


class EmailResetSecureSerializer(SMSOtpSerializerMixin, GoogleOtpSerializerMixin, ValidatePasswordMixin, BasicSerializer):
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
                is_active=True
            )

        except ValidationToken.DoesNotExist:
            self.token = None

        if not self.token:
            raise serializers.ValidationError(
                'Token is not valid.',
                code='invalid_secret')
        else:
            self.principal = self.token.principal



    def save(self, **kwargs):
        from talos.models import BasicIdentity
        self.token.principal.email = self.token.email
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()

        basic_credential = BasicIdentity.objects.get(
            principal=self.principal
        )
        basic_credential.email = self.token.email
        basic_credential.save()
        # TODO Send link to new email
        # TODO Send sms to old phone
        # TODO Send mail to old email for 5 days


class PhoneChangeRequestSerializer(BasicSerializer):
    token_type = 'phone_change'

    new_email = serializers.CharField(label='New E-mail')

    def __init__(self, *args, **kwargs):
        self.request = kwargs['context'].get('request')
        del kwargs['context']
        super(PhoneChangeRequestSerializer, self).__init__(*args, **kwargs)

    def validate_new_email(self, value):
        from talos.models import Principal

        new_email = value

        if not email_regex.match(new_email):
            raise serializers.ValidationError(
                'E-mail address is ill-formed.',
                code='invalid_email')

        try:
            principal = Principal.objects.get(email=new_email)

            raise serializers.ValidationError(
                'Principal with provided e-mail is already registered.',
                code='email_already_exists')
        except Principal.DoesNotExist:
            pass

        return new_email

    def save(self):

        new_email = self.validated_data['new_email']

        validation_token = ValidationToken()
        validation_token.email = new_email
        validation_token.principal = self.request.principal
        validation_token.type = self.token_type
        validation_token.save()


        # TODO SEND MAIL with link





class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(pk=2)
        self.principal = None
        super(PasswordResetRequestSerializer, self).__init__(*args, **kwargs)

    def validate_email(self, email):
        try:
            principal = Principal.objects.get(email=email)
            self.principal = principal
        except Principal.DoesNotExist:
            raise serializers.ValidationError("Email doesn't exists")
        return email

    def validate(self, attrs):
        return attrs

    def save(self):

        from django.core.mail import send_mail
        from django.template.loader import render_to_string
        from django.urls import reverse
        from talos.models import ValidationToken

        validation_token = ValidationToken()
        validation_token.email = self.validated_data['email']
        validation_token.principal = self.principal
        validation_token.type = 'password_reset'
        validation_token.save()

        # Send SMS Verification code to user
        if self.principal and self.principal.profile.is_secure is False:
            self.sms_otp_directory.create_credentials(self.principal, {})

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


class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()
    token = serializers.CharField()
    code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import BasicIdentityDirectory
        passed_kwargs_from_view = kwargs.get('context')

        self.sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(pk=2)
        self.basic_identity_directory = BasicIdentityDirectory.objects.get(
            code=passed_kwargs_from_view['identity_directory_code'])
        self.basic_credential_directory = self.basic_identity_directory.credential_directory
        self.google_authenticator_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        self.principal = None
        self.validation_token = None
        super(PasswordResetConfirmSerializer, self).__init__(*args, **kwargs)

    def validate_email(self, email):
        try:
            principal = Principal.objects.get(email=email)
            self.principal = principal
        except Principal.DoesNotExist:
            raise serializers.ValidationError("Email doesn't exists")
        return email

    def validate_password(self, password):
        return password

    def validate_token(self, token):
        try:
            validation_token = ValidationToken.objects.get(secret=token, principal=self.principal, is_active=True)
            self.validation_token = validation_token
        except ValidationToken.DoesNotExist:
            raise serializers.ValidationError("Token doesn't exits")
        return token

    def validate_code(self, code):
        if self.principal:
            if not self.principal.profile.is_secure and not self.sms_otp_directory.verify_credentials(self.principal, {'code' : code}):
                raise serializers.ValidationError("Code is incorrect")
            if self.principal.profile.is_secure and not self.google_authenticator_directory.verify_credentials(self.principal, {'code' : code}):
                raise serializers.ValidationError("Code is incorrect")
        return code

    def validate(self, attrs):
        return attrs

    def save(self):
        password = self.validated_data['password']

        if self.principal and self.basic_credential_directory:
            self.basic_credential_directory.reset_credentials(self.principal, self.principal, {'password' : password})

        if self.validation_token:
            self.validation_token.is_active = False
            self.validation_token.save()

