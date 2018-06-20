# from twilio.rest import Client
#
# # Your Account SID from twilio.com/console
# account_sid = "AC705961ce26e39cba6946ddbdc52ccfe2"
# # Your Auth Token from twilio.com/console
# auth_token  = "811faf06afe584ed7220bb486e9ba1e4"
#
# client = Client(account_sid, auth_token)
#
#
# def send_message(to, _from, body):
#     message = client.messages.create(
#         to=to,
#         from_='bixtrim',
#         body=body)
#
from talos.models import SMSProviders
import re


def _create_class_by_name(class_name):
    name_parts = class_name.split('.')
    module_name = '.'.join(name_parts[:-1])
    module = __import__(module_name)

    for name_part in name_parts[1:]:
        module = getattr(module, name_part)

    return module


class SMSSender(object):
    def __init__(self):
        self.backend_object = None

    def _ensure_backend(self, number):
        if not self.backend_object:
            sms_providers = SMSProviders.objects.all()
            for sms_provider in sms_providers:
                regex = re.compile(sms_provider.regex)
                if regex.match(number) is not None:
                    self.backend_object = _create_class_by_name(sms_provider.backend_class)()

        if not self.backend_object:
            # Choose default choice
            self.backend_object = _create_class_by_name('talos.sms_sender_backends.twilio.TwilioSender')()

    def send_message(self, number, message):
        self._ensure_backend(number)

        response = self.backend_object.send_message(number, message)

        if str(response.get('status', '')) == '400':
            return False
        return True