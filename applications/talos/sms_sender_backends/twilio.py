from django.conf import settings
import requests
from requests.auth import HTTPBasicAuth


class TwilioSender(object):
    def __init__(self):
        self.account_sid = 'AC705961ce26e39cba6946ddbdc52ccfe2'  # getattr(settings, 'TWILIO_ACCOUNT_SID')
        self.auth_token = '811faf06afe584ed7220bb486e9ba1e4'  # getattr(settings, 'TWILIO_AUTH_TOKEN')
        self.request_url = 'https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json'

    def send_message(self, to, message):
        data = {
            'From': 'bixtrim',  # getattr(settings, 'TWILIO_PHONE')
            'To': to,
            'Body': message
        }
        response = requests.post(self.request_url.format(self.account_sid),
                                 data=data,
                                 auth=HTTPBasicAuth(self.account_sid, self.auth_token)).json()

        return response

