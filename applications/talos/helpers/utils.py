import secrets
import string

from twilio.rest import Client

twilio_account_sid = 'AC9199f3572d9b0f0cf7709794e7221192'
twilio_auth_token = '398580003bffe706cd9293c4931472ac'


def send_message(to, _from, body):
    client = Client(twilio_account_sid, twilio_auth_token)
    message = client.messages.create(
        to=to,
        from_=_from,
        body=body)


def generate_random_number(length=10):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

