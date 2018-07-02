from talos.models import MessagingProviderDirectoryOption


class Nexmo(object):
    def __init__(self):
        self.message_options = MessagingProviderDirectoryOption.objects.filter(
            directory__code="nexmo")
        self.api_key = self.message_options.get(name="NEXMO_API_KEY").value
        self.api_secret = self.message_options.get(name="NEXMO_API_SECRET").value
        self.request_url = self.message_options.get(name="NEXMO_API_SECRET").value

    def send_message(self, to, message):
        from requests import post

        data = {
            'from': self.message_options.get(name="NEXMO_PHONE").value,
            'text': message,
            'to': to,
            'api_key': self.api_key,
            'api_secret': self.api_secret
        }

        response = post(self.request_url,
                        data=data).json()

        return response
