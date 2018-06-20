from django.core.handlers.exception import response_for_exception
from rest_framework.exceptions import APIException, _get_error_details, MethodNotAllowed
from rest_framework.views import exception_handler
from rest_framework import serializers, status
from django.core.validators import ValidationError as django_validation_error
from rest_framework.validators import ValidationError

def generate_docs_url(context):
    """ Generate docs urls based on request url and request method """

    http_method_to_action = {
        'GET': 'read',
        'POST': 'create',
        'DELETE': 'delete'

    }
    # This part generates urls from document GUI
    method = context['request']._request.method
    action_for_tests = http_method_to_action[method]
    absolute_url = (context['request'].build_absolute_uri())
    position = (absolute_url.find('/api/')) + len('/api/')
    absolute_url = absolute_url[:position] + 'docs/#' + absolute_url[position:].replace('/', '-') \
                   + '-' + action_for_tests
    return absolute_url


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
    """ This function runs after every exceptions raised anyware from code """

    response = exception_handler(exc, context)
    # Custom reposense data will be returned only if exception will be APIValidationError
    if isinstance(exc, APIValidationError):
        custom_response_data = {
            'status': exc.status_code,
            "error": exc.get_codes(),
            'details': exc.detail,
            'docs': generate_docs_url(context)
        }
        response.data = custom_response_data

    elif isinstance(exc, ValidationError):
        custom_response_data = {
            'status': exc.status_code,
            "error": exc.get_codes(),
            'details': exc.detail,
            'docs': generate_docs_url(context)
        }
        response.data = custom_response_data

    return response