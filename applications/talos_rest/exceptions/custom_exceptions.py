from rest_framework.exceptions import _get_error_details, APIException, MethodNotAllowed, PermissionDenied
from rest_framework.views import exception_handler
from rest_framework import status
from rest_framework.validators import ValidationError


# TODO move this class to separate file
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
        }
        response.data = custom_response_data

    elif isinstance(exc, ValidationError):
        custom_response_data = {
            'status': exc.status_code,
            "error": exc.get_codes(),
            'details': exc.detail,
        }
        response.data = custom_response_data

    elif isinstance(exc, MethodNotAllowed):
        custom_response_data = {
            'status': exc.status_code,
            "error": exc.get_codes(),
            'details': exc.detail,
        }
        response.data = custom_response_data

    elif isinstance(exc, PermissionDenied):
        custom_response_data = {
            'status': exc.status_code,
            "error": exc.get_codes(),
            'details': exc.detail,
        }
        response.data = custom_response_data

    return response
