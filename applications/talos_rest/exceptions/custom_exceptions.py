from rest_framework.exceptions import APIException, _get_error_details
from rest_framework.reverse import reverse_lazy
from rest_framework.views import exception_handler
from django.http import Http404
from rest_framework.serializers import ValidationError
from rest_framework import serializers, status



class APIValidationError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST

    def __init__(self, detail=None, code=None):
        if detail is None:
            detail = self.default_detail
        if code is None:
            code = self.default_code

        # For validation failures, we may collect many errors together,
        # so the details should always be coerced to a list if not already.
        if not isinstance(detail, dict) and not isinstance(detail, list):
            detail = [detail]

        self.detail = _get_error_details(detail, code)

def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    absolute_url =  (context['request'].build_absolute_uri())
    position = (absolute_url.find('/api/')) + len('/api/')
    absolute_url = absolute_url[:position] + 'docs/#' + absolute_url[position:]

    response = exception_handler(exc, context)

    if isinstance(exc, APIValidationError):
        custom_response_data = {
            'status' : exc.status_code,
            "error" : exc.get_codes(),
            'details': exc.detail, # custom exception message
            'docs' : absolute_url
        }
        response.data = custom_response_data # set the custom response data on response object

    return response