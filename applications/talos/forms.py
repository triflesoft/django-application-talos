from re import compile
from django import forms
from django.contrib.auth.password_validation import password_validators_help_texts

email_regex = compile(r'^[^@]+@[^@]+\.[^@]+$')


class PrincipalRegistrationRequestForm(forms.Form):
    email = forms.CharField(label='E-mail')

    def __init__(self, *args, **kwargs):
        self.request = kwargs['request']

        del kwargs['request']

        return super(PrincipalRegistrationRequestForm, self).__init__(*args, **kwargs)

    def clean_email(self):
        from .models import Principal

        email = self.cleaned_data['email']

        if not email_regex.match(email):
            raise forms.ValidationError(
                'E-mail address is ill-formed.',
                code='invalid_email')

        try:
            principal = Principal.objects.get(email=email)

            raise forms.ValidationError(
                'Principal with provided e-mail is already registered.',
                code='invalid_email')
        except Principal.DoesNotExist:
            pass

        return email

    def save(self):
        from django.core.mail import send_mail
        from django.template.loader import render_to_string
        from django.urls import reverse
        from .models import ValidationToken

        email = self.cleaned_data['email']

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

        mail_subject = render_to_string('talos/principal_registration/request_email_subject.txt', context)
        mail_body_text = render_to_string('talos/principal_registration/request_email_body.txt', context)
        mail_body_html = render_to_string('talos/principal_registration/request_email_body.html', context)

        send_mail(
            subject=mail_subject,
            message=mail_body_text,
            html_message=mail_body_html,
            from_email=None,
            recipient_list=[email],
            fail_silently=True)


class PrincipalRegistrationConfirmForm(forms.Form):
    brief_name = forms.CharField(
        label='Brief Name',
        max_length=255)
    full_name = forms.CharField(
        label='Full Name',
        max_length=255)
    username = forms.CharField(
        label='Username',
        max_length=255)
    password1 = forms.CharField(
        label='Password',
        strip=False,
        widget=forms.PasswordInput(),
        help_text=''.join('<p class="help is-success">{0}</p>'.format(text) for text in password_validators_help_texts()))
    password2 = forms.CharField(
        label='Password confirmation',
        strip=False,
        widget=forms.PasswordInput())

    def __init__(self, *args, **kwargs):
        from .models import BasicIdentityDirectory

        self.identity_directory = BasicIdentityDirectory.objects.get(code=kwargs['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.request = kwargs['request']
        self.token = kwargs['token']

        del kwargs['token']
        del kwargs['identity_directory_code']
        del kwargs['request']

        return super(PrincipalRegistrationConfirmForm, self).__init__(*args, **kwargs)

    def clean_username(self):
        username = self.cleaned_data['username']

        if self.identity_directory.get_principal({'username': username}):
            raise forms.ValidationError(
                'Username is already taken.',
                code='invalid_username')

        return username

    def clean_password1(self):
        from django.contrib.auth.password_validation import validate_password
        from .models import Principal

        username = self.cleaned_data.get('username', None)
        password1 = self.cleaned_data['password1']
        brief_name = self.cleaned_data.get('brief_name', None)
        full_name = self.cleaned_data.get('full_name', None)

        self.principal = Principal()
        self.principal.brief_name = brief_name
        self.principal.full_name = full_name
        self.principal.email = self.token.email

        validate_password(password1, self.principal)

        return password1

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1', None)
        password2 = self.cleaned_data['password2']

        if password1 and password2 and (password1 != password2):
            raise forms.ValidationError(
                'Passwords do not match.',
                code='invalid_password_confirmation')

        return password2

    def clean(self):
        if not self.token:
            raise forms.ValidationError(
                'Token is not valid.',
                code='invalid_secret')

    def save(self):
        username = self.cleaned_data['username']
        password1 = self.cleaned_data['password1']

        self.principal.save()
        self.identity_directory.create_credentials(self.principal, {'username': username})
        self.credential_directory.create_credentials(self.principal, {'password': password1})
        self.token.principal = self.principal
        self.token.is_active = False
        self.token.save()


class EmailChangeRequestForm(forms.Form):
    new_email = forms.CharField(label='New E-mail')

    def __init__(self, *args, **kwargs):
        self.request = kwargs['request']

        del kwargs['request']

        return super(EmailChangeRequestForm, self).__init__(*args, **kwargs)

    def clean_new_email(self):
        from .models import Principal

        new_email = self.cleaned_data['new_email']

        if not email_regex.match(new_email):
            raise forms.ValidationError(
                'E-mail address is ill-formed.',
                code='invalid_email')

        try:
            principal = Principal.objects.get(email=new_email)

            raise forms.ValidationError(
                'Principal with provided e-mail is already registered.',
                code='invalid_email')
        except Principal.DoesNotExist:
            pass

        return new_email

    def save(self):
        from django.core.mail import send_mail
        from django.template.loader import render_to_string
        from django.urls import reverse
        from .models import ValidationToken

        new_email = self.cleaned_data['new_email']

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

        mail_subject = render_to_string('talos/email_change/request_email_subject.txt', context)
        mail_body_text = render_to_string('talos/email_change/request_email_body.txt', context)
        mail_body_html = render_to_string('talos/email_change/request_email_body.html', context)

        send_mail(
            subject=mail_subject,
            message=mail_body_text,
            html_message=mail_body_html,
            from_email=None,
            recipient_list=[new_email],
            fail_silently=True)


class EmailChangeConfirmForm(forms.Form):
    new_email = forms.CharField(
        label='New E-mail',
        max_length=255)

    def __init__(self, *args, **kwargs):
        from .models import BasicIdentityDirectory

        self.request = kwargs['request']
        self.token = kwargs['token']

        del kwargs['token']
        del kwargs['request']

        return super(EmailChangeConfirmForm, self).__init__(*args, **kwargs)

    def clean(self):
        super(EmailChangeConfirmForm, self).clean()

        if not self.token or (self.token.principal != self.request.principal):
            raise forms.ValidationError(
                'Token is not valid.',
                code='invalid_secret')

    def save(self):
        self.token.principal.email = self.token.email
        self.token.principal.save()
        self.token.is_active = False
        self.token.save()


class BasicLoginForm(forms.Form):
    username = forms.CharField(label='Username')
    password = forms.CharField(label='Password', strip=False, widget=forms.PasswordInput())

    def __init__(self, *args, **kwargs):
        from .models import BasicIdentityDirectory

        self.identity_directory = BasicIdentityDirectory.objects.get(code=kwargs['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.evidences = list(self.credential_directory.provided_evidences.all())
        self.request = kwargs['request']

        del kwargs['identity_directory_code']
        del kwargs['request']

        return super(BasicLoginForm, self).__init__(*args, **kwargs)

    def clean_username(self):
        username = self.cleaned_data['username']

        self.principal = self.identity_directory.get_principal({'username': username})

        if not self.principal:
            raise forms.ValidationError(
                'Username is not valid. Note that username may be case-sensitive.',
                code='invalid_username')

        if not self.principal.is_active:
            raise forms.ValidationError(
                'Username is valid, but account is disabled.',
                code='invalid_username')

        return username

    def clean_password(self):
        password = self.cleaned_data['password']

        if not self.credential_directory.verify_credentials(self.principal, {'password': password}):
            raise forms.ValidationError(
                'Password is not valid. Note that password is case-sensitive.',
                code='invalid_password')

        return password

    def save(self):
        self.principal._load_authentication_context(self.evidences)
        self.request.principal = self.principal


class BasicPasswordChangeConfirmForm(forms.Form):
    principal = forms.CharField(label='Principal', disabled=True)
    old_password = forms.CharField(
        label='Old password',
        strip=False,
        widget=forms.PasswordInput())
    new_password1 = forms.CharField(
        label='New password',
        strip=False,
        widget=forms.PasswordInput(),
        help_text=''.join('<p class="help is-success">{0}</p>'.format(text) for text in password_validators_help_texts()))
    new_password2 = forms.CharField(
        label='New password confirmation',
        strip=False,
        widget=forms.PasswordInput())

    def __init__(self, *args, **kwargs):
        from .models import BasicIdentityDirectory

        self.identity_directory = BasicIdentityDirectory.objects.get(code=kwargs['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.request = kwargs['request']

        del kwargs['identity_directory_code']
        del kwargs['request']

        return super(BasicPasswordChangeConfirmForm, self).__init__(*args, **kwargs)

    def clean_password1(self):
        from django.contrib.auth.password_validation import validate_password

        old_password = self.cleaned_data['old_password']
        new_password1 = self.cleaned_data['new_password1']

        validate_password(new_password1, self.request.principal)

        if not self.credential_directory.verify_credentials(self.request.principal, {'password': old_password}):
            raise forms.ValidationError(
                'Old password is not valid. Note that password is case-sensitive.',
                code='invalid_password')

        return new_password1

    def clean_password2(self):
        new_password1 = self.cleaned_data['new_password1']
        new_password2 = self.cleaned_data['new_password2']

        if new_password1 != new_password2:
            raise forms.ValidationError(
                'New passwords do not match.',
                code='invalid_password_confirmation')

        return new_password2

    def save(self):
        old_password = self.cleaned_data['old_password']
        new_password1 = self.cleaned_data['new_password1']

        if not self.credential_directory.update_credentials(
            self.request.principal,
            {'password': old_password},
            {'password': new_password1}):
            raise forms.ValidationError(
                'Old password is not valid. Note that password is case-sensitive.',
                code='invalid_password')


class BasicPasswordResetRequestForm(forms.Form):
    email = forms.CharField(label='E-mail')

    def __init__(self, *args, **kwargs):
        self.request = kwargs['request']

        del kwargs['request']

        return super(BasicPasswordResetRequestForm, self).__init__(*args, **kwargs)

    def clean_email(self):
        from .models import Principal

        email = self.cleaned_data['email']

        if not email_regex.match(email):
            raise forms.ValidationError(
                'E-mail address is ill-formed.',
                code='invalid_email')

        try:
            self.principal = Principal.objects.get(email=email)
        except Principal.DoesNotExist:
            raise forms.ValidationError(
                'E-mail is not valid.',
                code='invalid_email')

        return email

    def save(self):
        from django.core.mail import send_mail
        from django.template.loader import render_to_string
        from django.urls import reverse
        from .models import ValidationToken

        validation_token = ValidationToken()
        validation_token.principal = self.principal
        validation_token.email = self.principal.email
        validation_token.type = 'password_reset'
        validation_token.save()

        context = {
            'url': '{0}://{1}{2}'.format(
                self.request.scheme,
                self.request.META['HTTP_HOST'],
                reverse('talos-basic-password-reset-token-edit', args=[validation_token.secret])),
            'principal': self.principal}

        mail_subject = render_to_string('talos/basic_password_reset/request_email_subject.txt', context)
        mail_body_text = render_to_string('talos/basic_password_reset/request_email_body.txt', context)
        mail_body_html = render_to_string('talos/basic_password_reset/request_email_body.html', context)

        send_mail(
            subject=mail_subject,
            message=mail_body_text,
            html_message=mail_body_html,
            from_email=None,
            recipient_list=[self.principal.email],
            fail_silently=True)


class BasicPasswordResetConfirmForm(forms.Form):
    new_password1 = forms.CharField(
        label='New password',
        strip=False,
        widget=forms.PasswordInput(),
        help_text=''.join('<p class="help is-success">{0}</p>'.format(text) for text in password_validators_help_texts()))
    new_password2 = forms.CharField(
        label='New password confirmation',
        strip=False,
        widget=forms.PasswordInput())

    def __init__(self, *args, **kwargs):
        from .models import BasicIdentityDirectory

        self.identity_directory = BasicIdentityDirectory.objects.get(code=kwargs['identity_directory_code'])
        self.credential_directory = self.identity_directory.credential_directory
        self.request = kwargs['request']
        self.token = kwargs['token']

        del kwargs['token']
        del kwargs['identity_directory_code']
        del kwargs['request']

        return super(BasicPasswordResetConfirmForm, self).__init__(*args, **kwargs)

    def clean_new_password1(self):
        from django.contrib.auth.password_validation import validate_password

        new_password1 = self.cleaned_data['new_password1']

        validate_password(new_password1, self.request.principal)

        return new_password1

    def clean_new_password2(self):
        new_password1 = self.cleaned_data.get('new_password1', None)
        new_password2 = self.cleaned_data['new_password2']

        if new_password1 and new_password2 and (new_password1 != new_password2):
            raise forms.ValidationError(
                'New passwords do not match.',
                code='invalid_password_confirmation')

        return new_password2

    def clean(self):
        super(BasicPasswordResetConfirmForm, self).clean()

        if not self.token:
            raise forms.ValidationError(
                'Token is not valid.',
                code='invalid_secret')

    def save(self):
        new_password1 = self.cleaned_data['new_password1']

        if not self.credential_directory.reset_credentials(
            self.token.principal,
            self.token.principal,
            {'password': new_password1}):
            raise forms.ValidationError(
                'Old password is not valid. Note that password is case-sensitive.',
                code='invalid_password')

        self.token.is_active = False
        self.token.save()
