from django.core.exceptions import ValidationError
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


class EmailChangeRequestSerializer(BasicSerializer):
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
        # TODO SEND MAIL
        from django.core.mail import send_mail
        from django.template.loader import render_to_string
        from django.urls import reverse
        from talos.models import ValidationToken

        new_email = self.validated_data['new_email']

        validation_token = ValidationToken()
        validation_token.email = new_email
        validation_token.principal = self.request.principal
        validation_token.type = 'email_change'
        validation_token.save()

        context = {
            'url': '{0}://{1}{2}'.format(
                self.request.scheme,
                self.request.META['HTTP_HOST'],
                reverse('talos-email-change-confirm-edit', args=[validation_token.secret])),
            'principal': validation_token.principal,
            'new_email': new_email}
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


class GoogleAuthenticatorActivateSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        self.salt = None
        super(GoogleAuthenticatorActivateSerializer, self).__init__(*args, **kwargs)

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
        # Create otp_credential for user
        if self.otp_credential_directory:
            salt = self.otp_credential_directory.create_credentials(self.principal, {})
            self.salt = salt


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
        if self.otp_credential_directory and not self.otp_credential_directory.verify_credentials(self.principal,
                                                                                                  {'code': value}):
            raise serializers.ValidationError('Code is incorrect')
        return value

    def save(self):
        for otp_evidence in self.otp_evidences:
            self.principal._evidences_effective[otp_evidence.code] = otp_evidence


class GoogleAuthenticatorDeleteSerializer(serializers.Serializer):
    code = serializers.CharField()

    def __init__(self, *args, **kwargs):
        from talos.models import OneTimePasswordCredentialDirectory
        passed_kwargs_from_view = kwargs.get('context')
        self.request = passed_kwargs_from_view['request']
        self.principal = self.request.principal
        self.otp_credential_directory = OneTimePasswordCredentialDirectory.objects.get(pk=1)
        super(GoogleAuthenticatorDeleteSerializer, self).__init__(*args, **kwargs)

    def validate_code(self, code):
        if self.otp_credential_directory and not self.otp_credential_directory.verify_credentials(self.principal, {'code' : code}):
            raise serializers.ValidationError('Your code is incorrect')
        return code

    def delete(self):
        if self.otp_credential_directory:
            self.otp_credential_directory.reset_credentials(self.principal,
                                                            self.principal,
                                                            {})


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
                                                                                    {'code' : code}):
            raise serializers.ValidationError('Code is incorrect')
        return code

    def validate(self, attrs):
        return attrs

    def save(self):
        for sms_otp_evidence in self.sms_otp_evidences:
            self.principal._evidences_effective[sms_otp_evidence.code] = sms_otp_evidence