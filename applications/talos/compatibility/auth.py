class AuthBackend(object):
    def __init__(self, *args, **kwargs):
        from ..models import BasicCredentialDirectory
        from ..models import BasicIdentityDirectory

        self.identity_directory = BasicIdentityDirectory.get_auth_directory()
        self.credential_directory = BasicCredentialDirectory.get_auth_directory()
        self.evidences = list(self.credential_directory.provided_evidences.filter(code__in=(
            'authenticated',
            'knowledge_factor',
            'knowledge_factor_password')))

    def authenticate(self, username=None, password=None):
        from ..models import BasicIdentity

        try:
            if self.identity_directory.is_active:
                basic_identity = self.identity_directory.identities.get(username=username)
                principal = basic_identity.principal

                if principal.check_password(password):
                    principal._load_authentication_context(self.evidences)

                    return principal
        except BasicIdentity.DoesNotExist:
            pass

        return None

    def get_user(self, user_id):
        from ..models import Principal

        try:
            principal = Principal.objects.get(id=user_id)
            principal._load_authentication_context(self.evidences)

            return principal
        except Principal.DoesNotExist:
            return None
