import pyotp

class InternalGoogleAuthenticator(object):
    def __init__(self, credential_directory, **kwargs):
        self._credential_directory = credential_directory


    def create_credentials(self, principal, credentials):
        from uuid import uuid4
        from ..models import _tzmin
        from ..models import _tzmax
        from ..models import BasicCredential, OneTimePasswordCredential


        OTP_credential = OneTimePasswordCredential()
        OTP_credential.uuid = uuid4()
        OTP_credential.principal = principal
        OTP_credential.valid_from = _tzmin()
        OTP_credential.valid_till = _tzmax()
        OTP_credential.directory = self._credential_directory
        base32_secret = pyotp.random_base32()
        OTP_credential.salt = base32_secret.encode()
        OTP_credential.save()

    def verify_credentials(self, principal, credentials):
        from ..models import _tznow
        from ..models import BasicCredential, OneTimePasswordCredential

        code = credentials['code']

        try:
            OTP_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            secret_key = OTP_credential.salt.decode()
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
            OTP_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())
            OTP_credential.delete()

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


        try:
            OTP_credential = OneTimePasswordCredential.objects.get(principal=principal,
                                                                   directory=self._credential_directory)
            OTP_credential.salt = utils.generate_random_number(length=6).encode()
            OTP_credential.save()
        except OneTimePasswordCredential.DoesNotExist:
            OTP_credential = OneTimePasswordCredential()
            OTP_credential.uuid = uuid4()
            OTP_credential.directory = self._credential_directory
            OTP_credential.principal = principal
            OTP_credential.valid_from = _tzmin()
            OTP_credential.valid_till = _tzmax()
            random_number = utils.generate_random_number(length=6)
            OTP_credential.salt = random_number.encode()
            OTP_credential.save()

        # Sending SMS using TWILIO
        utils.send_message(principal.phone, '+19144494290', body='Your registraion code is %s' % OTP_credential.salt.decode())


    def verify_credentials(self, principal, credentials):
        code = credentials['code']

        from ..models import _tznow
        from ..models import OneTimePasswordCredential

        try:
            OTP_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            secret_key = OTP_credential.salt.decode()

            if secret_key == code:
                return True

        except OneTimePasswordCredential.DoesNotExist as ex:
            pass

        return False



    def reset_credentials(self, super_principal,  principal, credentials):
        from ..models import _tznow
        from ..models import OneTimePasswordCredential

        try:
            OTP_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())
            OTP_credential.delete()

            return True
        except OneTimePasswordCredential.DoesNotExist:
            pass

        return False