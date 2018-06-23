# Replace with generic HTTP request
from django.conf import settings
import requests  # TODO too generic import


class Nexmo(object):
    def __init__(self):
        self.api_key = getattr(settings, 'NEXMO_API_KEY')
        self.api_secret = getattr(settings, 'NEXMO_API_SECRET')
        self.request_url = getattr(settings, 'NEXMO_API_SECRET')

    def send_message(self, to, message):
        data = {
            'from': getattr(settings, 'NEXMO_PHONE'),
            'text': message,
            'to': to,
            'api_key': self.api_key,
            'api_secret': self.api_secret
        }

        response = requests.post(self.request_url,
                                 data=data).json()

        return response
