class Internal(object):
    def __init__(self, identity_directory, **kwargs):
        self._identity_directory = identity_directory

    def create_credentials(self, principal, credentials):
        from uuid import uuid4
        from ..models import BasicIdentity

        username = credentials['username']

        basic_identity = BasicIdentity()
        basic_identity.uuid = uuid4()
        basic_identity.principal = principal
        basic_identity.directory = self._identity_directory
        basic_identity.username = username
        basic_identity.save()


    def get_principal(self, credentials):
        from ..models import BasicIdentity

        username = credentials['username']

        try:
            basic_identity = self._identity_directory.identities.get(email=username)

            return basic_identity.principal
        except BasicIdentity.DoesNotExist:
            pass

        return None
