import pyotp

class InternalPhoneSms(object):
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

            if totp.now() == code:
                return True
        except OneTimePasswordCredential.DoesNotExist as ex:
            pass

        return False

