from rest_framework import status


class SuccessResponse(object):
    def __init__(self, status=status.HTTP_200_OK, data={}):
        self._status = status
        self._data = {"status": status,
                      'result': data,
                      }

    @property
    def data(self):
        return self._data

    @property
    def status(self):
        return self._status

    def set_result_pairs(self, key, value):
        self.data['result'].update({key: value})


class ErrorResponse(object):
    def __init__(self, status=status.HTTP_400_BAD_REQUEST):
        self._status = status
        self._data = {
            'status': status,
            'error': {},
            'details': {}
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
    def data(self):
        return self._data

    @property
    def status(self):
        return self._status
