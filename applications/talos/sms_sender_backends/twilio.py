# Replace with generic HTTP request
from django.conf import settings
import requests  # TODO too generic import
from requests.auth import HTTPBasicAuth


class TwilioSender(object):
    def __init__(self):
        self.account_sid = getattr(settings, 'TWILIO_ACCOUNT_SID')
        self.auth_token = getattr(settings, 'TWILIO_AUTH_TOKEN')
        self.request_url = getattr(settings, "TWILIO_API_URL")

    def send_message(self, to, message):
        data = {
            'From': getattr(settings, 'TWILIO_PHONE'),
            'To': to,
            'Body': message
        }
        response = requests.post(self.request_url.format(self.account_sid),
                                 data=data,
                                 auth=HTTPBasicAuth(self.account_sid, self.auth_token)).json()

        return response
