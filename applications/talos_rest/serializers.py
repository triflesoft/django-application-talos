from rest_framework import serializers
from re import compile
from talos.models import Principal
#
from talos import middleware

email_regex = compile(r'^[^@]+@[^@]+\.[^@]+$')


class BasicLoginSerializer(serializers.Serializer):
    username = serializers.CharField(label='Username')
    password = serializers.CharField(label='Password')

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.identity_directory = BasicIdentityDirectory.objects.get(code=passed_kwargs_from_view['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.evidences = list(self.credential_directory.provided_evidences.all().order_by('id'))
        self.request = passed_kwargs_from_view['request']

        del passed_kwargs_from_view['identity_directory_code']
        del passed_kwargs_from_view['request']

        return super(BasicLoginSerializer, self).__init__(*args, **kwargs)

    def validate_username(self,value):
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

    def validate_password(self,value):
        password = value
        if self.principal and (not self.credential_directory.verify_credentials(self.principal, {'password': password})):
            raise serializers.ValidationError(
                'Password is not valid. Note that password is case-sensitive.',
                code='invalid_password')

        return password

    def save(self):
        self.principal._load_authentication_context(self.evidences)
        self.request.principal = self.principal


class PrincipalRegistrationRequestSerializer(serializers.Serializer):
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

            raise serializers.ValidationError('Principal with provided e-mail is already registered',
                                              code='invalid_email')
        except Principal.DoesNotExist:
            pass
        return email

    def save(self):
        from django.core.mail import send_mail
        from django.template.loader import render_to_string
        from django.urls import reverse
        from talos.models import ValidationToken

        email = self.validated_data['email']

        validation_token = ValidationToken()
        validation_token.email = email
        validation_token.type = 'principal_registration'
        validation_token.save()



        context = {
            'url': '{0}://{1}{2}'.format(
                self.request.scheme,
                self.request.META['HTTP_HOST'],
                reverse('talos-principal-registration-confirm-edit', args=[validation_token.secret])),
            'email': email}




class PrincipalRegistrationConfirmSerializer(serializers.Serializer):
    brief_name = serializers.CharField(label='Brief Name', max_length=255)
    full_name = serializers.CharField(label='Full Name', max_length=255)
    username = serializers.CharField(label='username', max_length=255)
    password1 = serializers.CharField(label='Password')
    password2 = serializers.CharField(label='Password Confirmation')

    def __init__(self, *args, **kwargs):
        from talos.models import BasicIdentityDirectory

        passed_kwargs_from_view = kwargs.get('context')
        self.identity_directory = BasicIdentityDirectory.objects.get(code=passed_kwargs_from_view['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.request = passed_kwargs_from_view.get('request')
        self.token = passed_kwargs_from_view.get('token')
        self.principal = None

        #del kwargs['context']['token']
        del kwargs['context']['identity_directory_code']
        del kwargs['context']['request']

        super(PrincipalRegistrationConfirmSerializer, self).__init__(*args, **kwargs)

    def validate_username(self, value):
        username = value

        if self.identity_directory.get_principal({'username' : username}):
            raise serializers.ValidationError('Username is already taken',
                                              code='invalid_username')

        return username

    def validate_password1(self, value):

        password1 = value



        return password1

    def validate_password2(self, value):
        #password1 = self.validated_data.get('password1', None)
        password2 = value #self.validated_data.get('password2', None)

        #if password1 and password2 and (password1 != password2):
        #    raise serializers.ValidationError('Passwords do not match.',
        #                                      code='invalid_password_confirmation')

        return password2

    def validate(self, attrs):
        if not self.token:
            raise serializers.ValidationError('Token is not valid.',
                                              code='invalid_token')

        return attrs


    def save(self):
        from django.contrib.auth.password_validation import validate_password

        username = self.validated_data['username']
        password = self.validated_data['password1']

        password1 = self.validated_data.get('password1', None)
        brief_name = self.validated_data.get('brief_name', None)
        full_name = self.validated_data.get('full_name', None)

        self.principal = Principal()
        self.principal.brief_name = brief_name
        self.principal.full_name = full_name
        self.principal.email = self.token.email

        validate_password(password1, self.principal)

        self.principal.save()
        self.identity_directory.create_credentials(self.principal, {'username' : username})
        self.credential_directory.create_credentials(self.principal, {'password' : password})
        self.token.principal = self.principal
        self.token.is_active = False
        self.token.save()






