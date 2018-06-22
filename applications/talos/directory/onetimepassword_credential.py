class InternalGoogleAuthenticator(object):
    def __init__(self, credential_directory, **kwargs):
        self._credential_directory = credential_directory

    def create_credentials(self, principal, credentials):
        from uuid import uuid4
        from ..models import _tzmin
        from ..models import _tzmax
        from ..models import OneTimePasswordCredential
        import pyotp

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
            base32_secret = pyotp.random_base32()
        otp_credential.salt = base32_secret.encode()
        otp_credential.save()
        return otp_credential.salt

    def verify_credentials(self, principal, credentials):
        from ..models import _tznow
        from ..models import OneTimePasswordCredential
        import pyotp

        code = credentials['code']

        try:
            otp_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            secret_key = otp_credential.salt.decode()
            totp = pyotp.TOTP(secret_key)

            if totp.verify(code):
                return True
        except OneTimePasswordCredential.DoesNotExist as ex:
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


class InternalPhoneSMS(object):
    def __init__(self, credential_directory, **kwargs):
        self._credential_directory = credential_directory

    def create_credentials(self, principal, credentials):
        from uuid import uuid4
        from ..models import OneTimePasswordCredential
        from ..models import _tzmin
        from ..models import _tzmax
        import pyotp

        otp_credential = OneTimePasswordCredential()
        otp_credential.uuid = uuid4()
        otp_credential.directory = self._credential_directory
        otp_credential.principal = principal
        otp_credential.valid_from = _tzmin()
        otp_credential.valid_till = _tzmax()
        base32_secret = pyotp.random_base32()
        otp_credential.salt = base32_secret.encode()
        otp_credential.save()

        # Sending SMS

    def verify_credentials(self, principal, credentials):
        code = credentials['code']
        from ..models import _tznow
        from ..models import OneTimePasswordCredential
        import pyotp

        try:
            otp_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            secret_key = otp_credential.salt.decode()
            totp = pyotp.TOTP(secret_key)

            if totp.verify(code):
                return True
        except OneTimePasswordCredential.DoesNotExist as ex:
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
        import pyotp
        from talos.models import OneTimePasswordCredential
        from ..contrib.sms_sender import SMSSender

        try:
            otp_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            secret_key = otp_credential.salt.decode()
            totp = pyotp.TOTP(secret_key)

            sms_sender = SMSSender()
            sms_sender.send_message(principal.phone, 'Your registraion code is %s' % totp.now())

            return True

        except OneTimePasswordCredential.DoesNotExist:
            pass
        return False
