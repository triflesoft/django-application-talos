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


def send_email(context, recipient_list, mail_subject, mail_body_text, mail_body_html):
    from django.template.loader import render_to_string
    from django.core.mail import send_mail

    mail_subject = render_to_string(mail_subject, context)
    mail_body_text = render_to_string(mail_body_text, context)
    mail_body_html = render_to_string(mail_body_html, context)

    send_mail(
        subject=mail_subject,
        message=mail_body_text,
        html_message=mail_body_html,
        from_email=None,
        recipient_list=recipient_list,
        fail_silently=True
    )
