class AuthBackend(object):
    def __init__(self, *args, **kwargs):
        from ..models import BasicCredentialDirectory
        from ..models import BasicIdentityDirectory

        self.identity_directory = BasicIdentityDirectory.get_auth_directory()
        self.credential_directory = BasicCredentialDirectory.get_auth_directory()
        self.evidences = list(self.credential_directory.provided_evidences.filter(code__in=(
            'authenticated',
            'knowledge_factor',
            'knowledge_factor_password')).order_by('id'))


    def authenticate(self, request, username=None, password=None, **kwargs):
        from ..models import BasicIdentity
        from ..models import Principal

        if self.identity_directory.is_active:
            try:
                basic_identity = self.identity_directory.identities.get(username=username)
                principal = basic_identity.principal
            except BasicIdentity.DoesNotExist:
                try:
                    principal = Principal.objects.get(email=username)
                except Principal.DoesNotExist:
                    principal = None

        if principal and principal.check_password(password):
            principal._load_authentication_context(self.evidences)

            return principal

        return None

    def get_user(self, user_id):
        from ..models import Principal

        try:
            principal = Principal.objects.get(id=user_id)
            principal._load_authentication_context(self.evidences)

            return principal
        except Principal.DoesNotExist:
            return None
