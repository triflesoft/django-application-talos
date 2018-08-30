class InternalGoogleAuthenticator(object):
    def __init__(self, credential_directory, **kwargs):
        self._credential_directory = credential_directory

    def create_credentials(self, principal, credentials):
        from pyotp import random_base32
        from uuid import uuid4
        from ..models import _tzmin
        from ..models import _tzmax
        from ..models import OneTimePasswordCredential

        otp_credential = OneTimePasswordCredential()
        otp_credential.uuid = uuid4()
        otp_credential.principal = principal
        otp_credential.valid_from = _tzmin()
        otp_credential.valid_till = _tzmax()
        otp_credential.directory = self._credential_directory

        if credentials.get('salt', None):
            base32_secret = credentials['salt']
            otp_credential.is_activated = True
        else:
            base32_secret = random_base32()

        otp_credential.salt = base32_secret.encode()
        otp_credential.save()

        return otp_credential.salt

    def verify_credentials(self, principal, credentials):
        from pyotp import TOTP
        from ..models import _tznow
        from ..models import OneTimePasswordCredential

        code = credentials['code']

        try:
            otp_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            secret_key = otp_credential.salt.decode()
            totp = TOTP(secret_key)

            if totp.verify(code):
                return True
        except OneTimePasswordCredential.DoesNotExist:
            pass

        return False

    def update_credentials(self, principal, old_credentials, new_credentials):
        from ..models import _tznow
        from ..models import OneTimePasswordCredential

        try:
            otp_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            if new_credentials.get('salt', None):
                otp_credential.salt = new_credentials['salt'].encode()
                otp_credential.save()
                return True
        except OneTimePasswordCredential.DoesNotExist:
            pass

        return False

    def reset_credentials(self, super_principal, principal, credentials):
        from ..models import _tznow
        from ..models import OneTimePasswordCredential

        try:
            otp_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())
            otp_credential.delete()

            return True
        except OneTimePasswordCredential.DoesNotExist:
            pass

        return False

    def generate_credentials(self, principal, credentials):
        return False

    def send_otp(self, principal, credential):
        pass

    def verify_otp(self, principal, credential, code):
        import pyotp

        # Type of salt is memoryview
        salt = credential.salt
        totp = pyotp.TOTP(salt.tobytes())

        return totp.verify(code)

class InternalPhoneSMS(object):
    def __init__(self, credential_directory, **kwargs):
        self._credential_directory = credential_directory

    def create_credentials(self, principal, credentials):
        from uuid import uuid4
        from ..models import OneTimePasswordCredential
        from ..models import _tzmin
        from ..models import _tzmax
        from pyotp import random_base32
        from talos.contrib.sms_sender import SMSSender
        import pyotp

        otp_credential = OneTimePasswordCredential()
        otp_credential.uuid = uuid4()
        otp_credential.directory = self._credential_directory
        otp_credential.principal = principal
        otp_credential.valid_from = _tzmin()
        otp_credential.valid_till = _tzmax()
        base32_secret = random_base32()
        otp_credential.salt = base32_secret.encode()
        otp_credential.save()


        totp = pyotp.TOTP(otp_credential.salt, interval=300)
        sms_sender = SMSSender()
        sms_sender.send_message(principal.phone, 'Your code is {}'.format(totp.now()))

    def verify_credentials(self, principal, credentials):
        code = credentials['code']
        from ..models import _tznow
        from ..models import OneTimePasswordCredential
        from pyotp import TOTP

        try:
            otp_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            secret_key = otp_credential.salt.decode()
            totp = TOTP(secret_key, interval=300)

            if totp.verify(code):
                return True
        except OneTimePasswordCredential.DoesNotExist:
            pass
        return False

    def reset_credentials(self, super_principal, principal, credentials):
        from ..models import _tznow
        from ..models import OneTimePasswordCredential

        try:
            otp_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())
            otp_credential.delete()

            return True
        except OneTimePasswordCredential.DoesNotExist:
            pass
        return False

    def generate_credentials(self, principal, credentials):
        from ..models import _tznow
        from pyotp import TOTP
        from talos.models import OneTimePasswordCredential
        from ..contrib.sms_sender import SMSSender

        try:
            otp_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            secret_key = otp_credential.salt.decode()
            totp = TOTP(secret_key)

            sms_sender = SMSSender()
            sms_sender.send_message(principal.phone, 'Your registraion code is %s' % totp.now())

            return True

        except OneTimePasswordCredential.DoesNotExist:
            pass
        return False

    def send_otp(self, principal, credential):
        import pyotp
        from ..contrib.sms_sender import SMSSender

        salt = credential.salt
        totp = pyotp.TOTP(salt, interval=300)

        sms_sender = SMSSender()
        sms_sender.send_message(principal.phone, totp.now())


    def verify_otp(self, principal, credential, code):
        import pyotp

        # Type of salt is memoryview
        salt = credential.salt
        # TODO: Remove .tobytes()
        totp = pyotp.TOTP(salt.tobytes(), interval=300)

        if totp.verify(code):
            return True
        return False
