import secrets
import string

from twilio.rest import Client

# twilio_account_sid = 'AC705961ce26e39cba6946ddbdc52ccfe2'
# twilio_auth_token = '811faf06afe584ed7220bb486e9ba1e4'
#
#
# def send_message(to, _from, body):
#     client = Client(twilio_account_sid, twilio_auth_token)
#     message = client.messages.create(
#         to=to,
#         from_=_from,
#         body=body)


def generate_random_number(length=10):
    characters = string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

