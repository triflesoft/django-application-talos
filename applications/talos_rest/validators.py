# This method validates mobile phone
# using Django's built in RegexpValidator
# And raises serializers.ValidationError if some
# error occurs
from talos_rest import constants

from re import compile

email_regex = compile(r'^[^@]+@[^@]+\.[^@]+$')


def validate_phone(phone, validate_uniqueness=False):
    from django.core.validators import RegexValidator
    from django.core.exceptions import ValidationError
    from talos.models import Principal

    from rest_framework import serializers

    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$',
                                 message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")

    if validate_uniqueness:
        try:
            Principal.objects.get(phone=phone)
            raise serializers.ValidationError("Phone is already used",
                                              code=constants.PHONE_USED_CODE)
        except Principal.DoesNotExist:
            pass

    try:
        phone_regex(phone)
    except ValidationError:
        raise serializers.ValidationError('Phone is invalid', code=constants.PHONE_INVALID_CODE)

    return phone


def validate_email(email, validate_uniqueness=False, validate_existance=False):
    from django.core.validators import validate_email as django_validate_email
    from django.core.exceptions import ValidationError
    from rest_framework import serializers
    from talos.models import Principal

    email = email.lower()

    if not email_regex.match(email):
        raise serializers.ValidationError(
            'E-mail address is ill-formed.',
            code=constants.EMAIL_INVALID_CODE)

    # Validate Uniqueness
    if validate_uniqueness:
        try:
            Principal.objects.get(email=email)
            raise serializers.ValidationError(
                'Principal with provided e-mail is already registered.',
                code=constants.EMAIL_USED_CODE)
        except Principal.DoesNotExist:
            pass

    # Validate non existance (User with this email should exists)
    if validate_existance:
        try:
            Principal.objects.get(email=email)
        except Principal.DoesNotExist:
            raise serializers.ValidationError(
                'Principal with provided email not exists',
                code=constants.EMAIL_INVALID_CODE)

    try:
        django_validate_email(email)
    except ValidationError:
        raise serializers.ValidationError('Email is invalid',
                                          code=constants.EMAIL_INVALID_CODE)

    return email

def validate_password(password):
    from django.contrib.auth.password_validation import validate_password
    from django.core.exceptions import ValidationError
    from rest_framework import serializers

    #try:
    #    validate_password(password)
    #except ValidationError:
    #    raise serializers.ValidationError('Invalid password format',
    #                                      code='password_invalid_format')
