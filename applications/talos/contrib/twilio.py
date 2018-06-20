from twilio.rest import Client

# Your Account SID from twilio.com/console
account_sid = "AC705961ce26e39cba6946ddbdc52ccfe2"
# Your Auth Token from twilio.com/console
auth_token  = "811faf06afe584ed7220bb486e9ba1e4"

client = Client(account_sid, auth_token)


def send_message(to, _from, body):
    message = client.messages.create(
        to=to,
        from_='bixtrim',
        body=body)


def generate_random_number(length=10):
    import string
    import secrets

    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

