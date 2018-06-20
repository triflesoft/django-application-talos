from logging import getLogger


logger = getLogger('talos')


class Internal(object):
    def __init__(self, credential_directory, **kwargs):
        self._credential_directory = credential_directory

    def verify_credentials(self, principal, credentials):
        from ..models import _tznow
        from ..models import BasicCredential

        password = credentials['password']

        try:
            basic_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            if basic_credential.verify_password(password):
                return True
        except BasicCredential.DoesNotExist:
            pass

        logger.debug('TALOS: Basic credential verification failed for "%s".', principal.email)

        return False

    def create_credentials(self, principal, credentials):
        from uuid import uuid4
        from ..models import _tzmin
        from ..models import _tzmax
        from ..models import BasicCredential

        password = credentials['password']

        basic_credential = BasicCredential()
        basic_credential.uuid = uuid4()
        basic_credential.principal = principal
        basic_credential.valid_from = _tzmin()
        basic_credential.valid_till = _tzmax()
        basic_credential.directory = self._credential_directory
        basic_credential.algorithm_name = 'pbkdf2'
        basic_credential.algorithm_rounds = 100000
        basic_credential.force_change = False
        basic_credential.set_password(password)
        basic_credential.save()

    def update_credentials(self, principal, old_credentials, new_credentials):
        from ..models import _tznow
        from ..models import BasicCredential

        old_password = old_credentials['password']
        new_password = new_credentials['password']

        try:
            basic_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())

            if basic_credential.verify_password(old_password):
                basic_credential.set_password(new_password)
                basic_credential.save()

                return True
        except BasicCredential.DoesNotExist:
            pass

        logger.debug('TALOS: Basic credential update failed for "%s".', principal.email)

        return False

    def reset_credentials(self, super_principal, principal, new_credentials):
        from ..models import _tznow
        from ..models import BasicCredential

        new_password = new_credentials['password']

        try:
            basic_credential = self._credential_directory.credentials.get(
                principal=principal,
                valid_from__lte=_tznow(),
                valid_till__gte=_tznow())
            basic_credential.set_password(new_password)
            basic_credential.save()

            return True
        except BasicCredential.DoesNotExist:
            pass

        logger.debug('TALOS: Basic credential reset failed for "%s".', principal.email)

        return False

class Ldap(object):
    def __init__(self, credential_directory, **kwargs):
        self._credential_directory = credential_directory

    def verify_credentials(self, principal, credentials):
        from talos.contrib.ldap import LdapConnection
        password = credentials['password']

        ldap_connection = LdapConnection()
        ldap_connection.connect()

        try:
            ldap_connection.check_credentials(principal.email, password)
            return True
        except:
            pass

        logger.debug('TALOS: LDAP credential verification failed for "%s".', principal.email)

        return False