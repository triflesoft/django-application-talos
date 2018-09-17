from talos.models import MessagingProviderDirectoryOption

class TwilioSender(object):
    def __init__(self):
        self.message_options = MessagingProviderDirectoryOption.objects.filter(
            directory__code="twilio")

        self.account_sid = self.message_options.get(name="TWILIO_ACCOUNT_SID").value
        self.auth_token = self.message_options.get(name="TWILIO_AUTH_TOKEN").value
        self.request_url = self.message_options.get(name="TWILIO_API_URL").value
        self.from_number = self.message_options.get(name="TWILIO_PHONE").value

    def send_message(self, to, message):
        from requests.auth import HTTPBasicAuth
        from requests import post


        for number in self.from_number.split(','):
            data = {
                'From': number,
                'To': to,
                'Body': message
            }

            response = post(self.request_url.format(self.account_sid),
                            data=data,
                            auth=HTTPBasicAuth(self.account_sid, self.auth_token)).json()

            print(response)

            if response.get('status', 0) == 400 and \
                    (response.get('code', 0) == 21612 or response.get('code', 0) == 21606):
                continue
            else:
                return response
        return {}



