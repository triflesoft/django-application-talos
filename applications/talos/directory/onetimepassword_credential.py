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
        base32_secret = pyotp.random_base32()
        otp_credential.salt = base32_secret.encode()
        otp_credential.save()
        return otp_credential.salt

    def verify_credentials(self, principal, credentials):
        from ..models import _tznow
        from ..models import BasicCredential, OneTimePasswordCredential
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
                # If verified and not activated, this means verificiation
                # happens first time
                if otp_credential.is_activated is False:
                    otp_credential.is_activated = True
                    otp_credential.save()
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


class InternalPhoneSMS(object):
    def __init__(self, credential_directory, **kwargs):
        self._credential_directory = credential_directory

    def create_credentials(self, principal, credentials):
        from uuid import uuid4
        from ..models import OneTimePasswordCredential
        from ..models import _tzmin
        from ..models import _tzmax
        from ..helpers import utils
        from ..contrib import twilio

        try:
            otp_credential = OneTimePasswordCredential.objects.get(principal=principal,
                                                                   directory=self._credential_directory)
            otp_credential.salt = utils.generate_random_number(length=6).encode()
            otp_credential.save()
        except OneTimePasswordCredential.DoesNotExist:
            otp_credential = OneTimePasswordCredential()
            otp_credential.uuid = uuid4()
            otp_credential.directory = self._credential_directory
            otp_credential.principal = principal
            otp_credential.valid_from = _tzmin()
            otp_credential.valid_till = _tzmax()
            random_number = utils.generate_random_number(length=6)
            otp_credential.salt = random_number.encode()
            otp_credential.save()

        # Sending SMS using TWILIO
        twilio.send_message(principal.phone, '+19144494290', body='Your registraion code is %s' % otp_credential.salt.decode())

    def verify_credentials(self, principal, credentials):
        code = credentials['code']
        from ..models import _tznow
        from ..models import OneTimePasswordCredential
        try:
            otp_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            secret_key = otp_credential.salt.decode()
            if secret_key == code:
                # If verified and is_activated is False this means
                # activation happens first time
                if otp_credential.is_activated is False:
                    otp_credential.is_activated = True
                    otp_credential.save()
                return True
        except OneTimePasswordCredential.DoesNotExist as ex:
            pass
        return False

    def reset_credentials(self, super_principal,  principal, credentials):
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