# This method validates mobile phone
# using Django's built in RegexpValidator
# And raises serializers.ValidationError if some
# error occurs
from talos_rest import constants


def validate_phone(phone):
    from django.core.validators import RegexValidator
    from django.core.exceptions import ValidationError

    from rest_framework import serializers

    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$',
                                 message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")

    try:
        phone_regex(phone)
    except ValidationError:
        raise serializers.ValidationError('Phone is invalid',
                                          code=constants.PHONE_INVALID_CODE)


def validate_email(email):
    from django.core.validators import validate_email as django_validate_email
    from django.core.exceptions import ValidationError
    from rest_framework import serializers

    try:
        django_validate_email(email)
    except ValidationError:
        raise serializers.ValidationError('Email is invalid',
                                          code=constants.EMAIL_INVALID_CODE)


def validate_password(password):
    pass
