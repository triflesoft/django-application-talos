from rest_framework import status

class SuccessResponse(object):
    def __init__(self,code=status.HTTP_200_OK):
        self._code = code
        self._data = {"status": code,
                     'result': {}
                     }
    @property
    def data(self):
        return self._data
    @property
    def status(self):
        return self._code

    def set_result_pairs(self, key, value):
        self.data['result'].update({key: value})


class ErrorResponse(object):
    def __init__(self, code=status.HTTP_400_BAD_REQUEST):
        self.code = code
        self.data = {
            'status': code,
            'error': {},
            'details': {},
            'docs': None
        }

    def set_error_pairs(self, key, value):
        if type(value) is not list:
            value = [value]
        self.data['error'].update({key: value})

    def set_details_pairs(self, key, value):
        if type(value) is not list:
            value = [value]
        self.data['details'].update({key: value})

    def set_docs(self, value):
        self.data['docs'] = value

    @property
    def response(self):
        return self.data