from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils.text import slugify
from socket import gethostname
from uuid import uuid4

models.options.DEFAULT_NAMES = \
    models.options.DEFAULT_NAMES + \
    ('object_permissions', 'model_permissions', 'related_securables')

VALIDATION_TOKEN_TYPE_CHOICES = [
    ('principal_registration', 'Principal registration'),
    ('password_reset', 'Password reset'),
    ('email_change', 'E-mail change'),
]


def _tznow():
    from datetime import datetime
    from pytz import utc

    return datetime.utcnow().replace(tzinfo=utc)


def _tzmin():
    from datetime import datetime
    from pytz import utc

    return datetime.min.replace(tzinfo=utc)


def _tzmax():
    from datetime import datetime
    from pytz import utc

    return datetime.max.replace(tzinfo=utc)


def _create_class_by_name(class_name):
    name_parts = class_name.split('.')
    module_name = '.'.join(name_parts[:-1])
    module = __import__(module_name)

    for name_part in name_parts[1:]:
        module = getattr(module, name_part)

    return module


_hostname = gethostname()


def _default_hostname():
    return _hostname


class AbstractReplicatableModel(models.Model):
    id = models.AutoField(unique=True, primary_key=True)
    uuid = models.UUIDField(unique=True, default=uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    modified_at = models.DateTimeField(auto_now=True, editable=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, related_name='+',
                                   on_delete=models.CASCADE, editable=False)
    modified_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, related_name='+',
                                    on_delete=models.CASCADE, editable=False)
    created_on = models.CharField(max_length=255, default=_default_hostname)
    modified_on = models.CharField(max_length=255, default=_default_hostname)

    class Meta:
        abstract = True


class AbstractObjectPermission(models.Model):
    id = models.AutoField(unique=True, primary_key=True)
    role = models.ForeignKey('talos.Role', related_name='+', on_delete=models.CASCADE)
    action = models.ForeignKey('talos.ObjectAction', related_name='+', on_delete=models.CASCADE)
    # target = models.ForeignKey(SECURABLE_MODEL, related_name='permissions', on_delete=models.CASCADE)
    _talos_object_permission = True

    class Meta:
        abstract = True
        unique_together = [
            ('role', 'action', 'target')]
        index_together = [
            ('target', 'action', 'role'),
            ('target', 'role', 'action'),
            ('role', 'target', 'action')]


class Evidence(AbstractReplicatableModel):
    code = models.SlugField(unique=True, max_length=255, allow_unicode=True)
    name = models.CharField(unique=True, max_length=255)
    expiration_period = models.PositiveIntegerField(default=3600)

    class Meta:
        model_permissions = '__all__'
        verbose_name = 'Evidence'
        verbose_name_plural = 'Evidence'

    def __str__(self):
        return self.name


class AbstractDirectory(AbstractReplicatableModel):
    backend_class = models.CharField(max_length=255)
    priority = models.PositiveIntegerField(default=1)
    is_active = models.BooleanField(default=True)
    code = models.SlugField(unique=True, max_length=255, allow_unicode=True)
    name = models.CharField(unique=True, max_length=255)

    class Meta:
        abstract = True

    def _get_options_cache(self):
        options_cache = getattr(self, '_options_cache', None)

        if not options_cache:
            options_cache = {option.name: option.value for option in self.options.all()}
            setattr(self, '_options_cache', options_cache)

        return options_cache

    def __getitem__(self, option_name):
        options_cache = self._get_options_cache()

        return options_cache[option_name]

    def get(self, option_name, default_value):
        options_cache = self._get_options_cache()

        return options_cache.get(option_name, default_value)

    def __str__(self):
        return self.name


class AbstractRoleDirectory(AbstractDirectory):
    # required_evidence = models.ManyToManyField(Evidence, related_name='+')

    class Meta:
        abstract = True


class AbstractIdentityDirectory(AbstractDirectory):
    class Meta:
        abstract = True


class AbstractCredentialDirectory(AbstractDirectory):
    # provided_evidences = models.ManyToManyField(Evidence, related_name='+')

    class Meta:
        abstract = True


class AbstractIdentity(AbstractReplicatableModel):
    principal = models.ForeignKey('talos.Principal', related_name='+', on_delete=models.CASCADE)

    class Meta:
        abstract = True


class AbstractCredential(AbstractReplicatableModel):
    principal = models.ForeignKey('talos.Principal', related_name='+', on_delete=models.CASCADE)
    valid_from = models.DateTimeField(default=_tznow)
    valid_till = models.DateTimeField(default=_tzmax)

    class Meta:
        abstract = True


class Privilege(AbstractReplicatableModel):
    code = models.SlugField(unique=True, max_length=255, allow_unicode=True)
    name = models.CharField(unique=True, max_length=255)

    class Meta:
        model_permissions = ()
        verbose_name = 'Privilege'
        verbose_name_plural = 'Privileges'

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = slugify(self.name)

        super(Privilege, self).save(*args, **kwargs)

    def __str__(self):
        return self.name


class ModelAction(AbstractReplicatableModel):
    application = models.CharField(max_length=255)
    model = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    code = models.SlugField(unique=True, max_length=255, allow_unicode=True)
    name = models.CharField(unique=True, max_length=255)
    content_type = models.ForeignKey(ContentType, related_name='+', on_delete=models.CASCADE)

    class Meta:
        model_permissions = ()
        verbose_name = 'Model Action'
        verbose_name_plural = 'Model Actions'

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = slugify(self.name)

        super(ModelAction, self).save(*args, **kwargs)

    def __str__(self):
        return self.name


class ObjectAction(AbstractReplicatableModel):
    application = models.CharField(max_length=255)
    model = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    code = models.SlugField(unique=True, max_length=255, allow_unicode=True)
    name = models.CharField(unique=True, max_length=255)
    content_type = models.ForeignKey(ContentType, related_name='+', on_delete=models.CASCADE)

    class Meta:
        unique_together = [
            ('application', 'model', 'action'),
            ('content_type', 'action')]
        model_permissions = ()
        verbose_name = 'Object Action'
        verbose_name_plural = 'Object Actions'

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = slugify(self.name)

        super(ObjectAction, self).save(*args, **kwargs)

    def __str__(self):
        return self.name


class RoleDirectory(AbstractRoleDirectory):
    required_evidences = models.ManyToManyField(Evidence, related_name='+', through='RoleDirectoryRequiredEvidence')

    class Meta:
        model_permissions = '__all__'
        object_permissions = '__all__'
        verbose_name = 'Role Directory'
        verbose_name_plural = 'Role Directories'


class RoleDirectoryObjectPermission(AbstractObjectPermission):
    target = models.ForeignKey(RoleDirectory, related_name='permissions', on_delete=models.CASCADE)


class RoleDirectoryRequiredEvidence(AbstractReplicatableModel):
    directory = models.ForeignKey(RoleDirectory, related_name='+', on_delete=models.CASCADE)
    evidence = models.ForeignKey(Evidence, related_name='+', on_delete=models.CASCADE)

    class Meta:
        unique_together = [
            ('directory', 'evidence')]
        model_permissions = ()
        verbose_name = 'Evidence Required for Role Directory'
        verbose_name_plural = 'Evidences Required for Role Directory'

    def __str__(self):
        return ''


class RoleDirectoryOption(AbstractReplicatableModel):
    directory = models.ForeignKey(RoleDirectory, related_name='options', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    value = models.TextField()

    class Meta:
        unique_together = [
            ('directory', 'name')]
        model_permissions = ()

    def __str__(self):
        return '"{0}" ("{1}")'.format(self.name, self.directory.name)


class Role(AbstractReplicatableModel):
    directory = models.ForeignKey(RoleDirectory, related_name='roles', on_delete=models.CASCADE)
    code = models.SlugField(unique=True, max_length=255, allow_unicode=True)
    name = models.CharField(unique=True, max_length=255)
    parent = models.ForeignKey('self', blank=True, null=True, related_name='children', on_delete=models.CASCADE)
    privilege_permissions_granted = models.ManyToManyField(Privilege, related_name='+',
                                                           through='RolePrivilegePermissionGranted')
    privilege_permissions_revoked = models.ManyToManyField(Privilege, related_name='+',
                                                           through='RolePrivilegePermissionRevoked')
    privilege_permissions_effective = models.ManyToManyField(Privilege, related_name='+',
                                                             through='RolePrivilegePermissionEffective')
    model_action_permissions_granted = models.ManyToManyField(ModelAction, related_name='+',
                                                              through='RoleModelActionPermissionGranted')
    model_action_permissions_revoked = models.ManyToManyField(ModelAction, related_name='+',
                                                              through='RoleModelActionPermissionRevoked')
    model_action_permissions_effective = models.ManyToManyField(ModelAction, related_name='+',
                                                                through='RoleModelActionPermissionEffective')

    class Meta:
        unique_together = [
            ('directory', 'code'),
            ('directory', 'name')]
        model_permissions = '__all__'
        object_permissions = '__all__'
        related_securables = ('directory',)
        verbose_name = 'Role'
        verbose_name_plural = 'Roles'

    def _update_effective_permission_sets(self, all_privileges, all_model_actions):
        if self.parent is None:
            parent_privilege_effective_ids = set()
            parent_model_action_effective_ids = set()
        else:
            parent_privilege_effective_ids = set(
                id for id in self.parent.privilege_permissions_effective.all().values_list('id', flat=True))
            parent_model_action_effective_ids = set(
                id for id in self.parent.model_action_permissions_effective.all().values_list('id', flat=True))

        granted_privilege_ids = set(id for id in self.privilege_permissions_granted.all().values_list('id', flat=True))
        revoked_privilege_ids = set(id for id in self.privilege_permissions_revoked.all().values_list('id', flat=True))
        old_effective_privilege_ids = set(
            id for id in self.privilege_permissions_effective.all().values_list('id', flat=True))

        new_effective_privilege_ids = set()
        new_effective_privilege_ids |= parent_privilege_effective_ids
        new_effective_privilege_ids |= granted_privilege_ids
        new_effective_privilege_ids -= revoked_privilege_ids
        create_effective_privilege_ids = new_effective_privilege_ids - old_effective_privilege_ids
        delete_effective_privilege_ids = old_effective_privilege_ids - new_effective_privilege_ids

        RolePrivilegePermissionEffective.objects.filter(privilege__id__in=delete_effective_privilege_ids).delete()
        RolePrivilegePermissionEffective.objects.bulk_create([
            RolePrivilegePermissionEffective(
                role=self,
                privilege=all_privileges[id]) for id in create_effective_privilege_ids
        ])

        granted_model_action_ids = set(
            id for id in self.model_action_permissions_granted.all().values_list('id', flat=True))
        revoked_model_action_ids = set(
            id for id in self.model_action_permissions_revoked.all().values_list('id', flat=True))
        old_effective_model_action_ids = set(
            id for id in self.model_action_permissions_effective.all().values_list('id', flat=True))
        new_effective_model_action_ids = set()
        new_effective_model_action_ids |= parent_model_action_effective_ids
        new_effective_model_action_ids |= granted_model_action_ids
        new_effective_model_action_ids -= revoked_model_action_ids
        create_effective_model_action_ids = new_effective_model_action_ids - old_effective_model_action_ids
        delete_effective_model_action_ids = old_effective_model_action_ids - new_effective_model_action_ids

        RoleModelActionPermissionEffective.objects.filter(
            model_action__id__in=delete_effective_model_action_ids).delete()
        RoleModelActionPermissionEffective.objects.bulk_create([
            RoleModelActionPermissionEffective(
                role=self,
                model_action=all_model_actions[id]) for id in create_effective_model_action_ids
        ])

        for role in self.children.all():
            role._update_effective_permission_sets(all_privileges, all_model_actions)

    def update_effective_permission_sets(self):
        all_privileges = {privilege.id: privilege for privilege in Privilege.objects.all()}
        all_model_actions = {model_action.id: model_action for model_action in ModelAction.objects.all()}

        self._update_effective_permission_sets(all_privileges, all_model_actions)

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = slugify(self.name)

        super(Role, self).save(*args, **kwargs)

    def __str__(self):
        return self.name


class RoleObjectPermission(AbstractObjectPermission):
    target = models.ForeignKey(Role, related_name='permissions', on_delete=models.CASCADE)


class RolePrivilegePermissionGranted(AbstractReplicatableModel):
    role = models.ForeignKey(Role, related_name='+', on_delete=models.CASCADE)
    privilege = models.ForeignKey(Privilege, related_name='+', on_delete=models.CASCADE)

    class Meta:
        unique_together = [
            ('role', 'privilege')]
        index_together = [
            ('privilege', 'role')]
        model_permissions = ()
        verbose_name = 'Privilege Permission Granted to a Role'
        verbose_name_plural = 'Privilege Permissions Granted to a Role'


class RolePrivilegePermissionRevoked(AbstractReplicatableModel):
    role = models.ForeignKey(Role, related_name='+', on_delete=models.CASCADE)
    privilege = models.ForeignKey(Privilege, related_name='+', on_delete=models.CASCADE)

    class Meta:
        unique_together = [
            ('role', 'privilege')]
        index_together = [
            ('privilege', 'role')]
        model_permissions = ()
        verbose_name = 'Privilege Permission Revoked from a Role'
        verbose_name_plural = 'Privilege Permissions Revoked from a Role'


class RolePrivilegePermissionEffective(AbstractReplicatableModel):
    role = models.ForeignKey(Role, related_name='+', on_delete=models.CASCADE)
    privilege = models.ForeignKey(Privilege, related_name='+', on_delete=models.CASCADE)

    class Meta:
        unique_together = [
            ('role', 'privilege')]
        index_together = [
            ('privilege', 'role')]
        model_permissions = ()
        verbose_name = 'Effective Privilege Permission of a Role'
        verbose_name_plural = 'Effective Privilege Permissions of a Role'


class RoleModelActionPermissionGranted(AbstractReplicatableModel):
    role = models.ForeignKey(Role, related_name='+', on_delete=models.CASCADE)
    model_action = models.ForeignKey(ModelAction, related_name='+', on_delete=models.CASCADE)

    class Meta:
        unique_together = [
            ('role', 'model_action')]
        index_together = [
            ('model_action', 'role')]
        model_permissions = ()
        verbose_name = 'Model Action Permission Granted to Role'
        verbose_name_plural = 'Model Action Permissions Granted to Role'


class RoleModelActionPermissionRevoked(AbstractReplicatableModel):
    role = models.ForeignKey(Role, related_name='+', on_delete=models.CASCADE)
    model_action = models.ForeignKey(ModelAction, related_name='+', on_delete=models.CASCADE)

    class Meta:
        unique_together = [
            ('role', 'model_action')]
        index_together = [
            ('model_action', 'role')]
        model_permissions = ()
        verbose_name = 'Model Action Permission Revoked from Role'
        verbose_name_plural = 'Model Action Permissions Revoked from Role'


class RoleModelActionPermissionEffective(AbstractReplicatableModel):
    role = models.ForeignKey(Role, related_name='+', on_delete=models.CASCADE)
    model_action = models.ForeignKey(ModelAction, related_name='+', on_delete=models.CASCADE)

    class Meta:
        unique_together = [
            ('role', 'model_action')]
        index_together = [
            ('model_action', 'role')]
        model_permissions = ()
        verbose_name = 'Effective Model Action Permission of a Role'
        verbose_name_plural = 'Effective Model Action Permissions of a Role'


class PrincipalRoleMembership(AbstractReplicatableModel):
    principal = models.ForeignKey('talos.Principal', related_name='+', on_delete=models.CASCADE)
    role = models.ForeignKey(Role, related_name='principals', on_delete=models.CASCADE)

    class Meta:
        unique_together = [
            ('principal', 'role')]
        index_together = [
            ('role', 'principal')]
        verbose_name = 'Principal Membership'
        verbose_name_plural = 'Principal Membership'
        model_permissions = ()
        related_securables = ('principal', 'role',)

    def __str__(self):
        return '"{0}"-"{1}"'.format(self.principal, self.role)


class Realm(AbstractReplicatableModel):
    brief_name = models.CharField(blank=True, max_length=255)
    full_name = models.CharField(blank=True, max_length=255)
    email = models.EmailField(blank=True, max_length=255)

    class Meta:
        model_permissions = '__all__'
        verbose_name = 'Realm'
        verbose_name_plural = 'Realms'

    def __str__(self):
        return self.full_name or self.brief_name or self.email


class BasicIdentityDirectory(AbstractIdentityDirectory):
    realm = models.ForeignKey(Realm, null=True, blank=True, related_name='+', on_delete=models.CASCADE)
    credential_directory = models.ForeignKey('BasicCredentialDirectory', null=True, blank=True,
                                             related_name='identity_directories', on_delete=models.CASCADE)

    class Meta:
        model_permissions = '__all__'
        object_permissions = '__all__'
        verbose_name = 'Basic Identity Directory'
        verbose_name_plural = 'Basic Identity Directories'

    @staticmethod
    def get_auth_directory():
        return BasicIdentityDirectory.objects.get(
            code=getattr(settings, 'TALOS_AUTH_DEFAULT_IDENTITY_DIRECTORY', 'basic_internal'))

    def __init__(self, *args, **kwargs):
        super(BasicIdentityDirectory, self).__init__(*args, **kwargs)
        self.backend_object = None

    def _ensure_backend(self):
        if not self.backend_object:
            self.backend_object = _create_class_by_name(self.backend_class)(self)

    def create_credentials(self, principal, credentials):
        self._ensure_backend()

        return self.backend_object.create_credentials(principal, credentials)

    def get_principal(self, credentials):
        self._ensure_backend()

        return self.backend_object.get_principal(credentials)


class BasicIdentityDirectoryObjectPermission(AbstractObjectPermission):
    target = models.ForeignKey(BasicIdentityDirectory, related_name='permissions', on_delete=models.CASCADE)


class BasicIdentityDirectoryOption(AbstractReplicatableModel):
    directory = models.ForeignKey(BasicIdentityDirectory, related_name='options', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    value = models.TextField()

    class Meta:
        model_permissions = ()

    def __str__(self):
        return '"{0}" ("{1}")'.format(self.name, self.directory.name)


class BasicIdentity(AbstractIdentity):
    directory = models.ForeignKey(BasicIdentityDirectory, related_name='identities', on_delete=models.CASCADE)
    username = models.CharField(max_length=255)
    email = models.CharField(max_length=255, default='default_email')

    class Meta:
        unique_together = [
            ('directory', 'username')]
        model_permissions = '__all__'
        related_securables = ('principal', 'directory')
        verbose_name = 'Basic Identity'
        verbose_name_plural = 'Basic Identities'

    def __str__(self):
        return '"{0}" ("{1}")'.format(
            self.username,
            self.directory.name)


class BasicCredentialDirectory(AbstractCredentialDirectory):
    class Meta:
        model_permissions = '__all__'
        object_permissions = '__all__'
        verbose_name = 'Basic Credential Directory'
        verbose_name_plural = 'Basic Credential Directories'

    @staticmethod
    def get_auth_directory():
        return BasicCredentialDirectory.objects.get(
            code=getattr(settings, 'TALOS_AUTH_DEFAULT_CREDENTIAL_DIRECTORY', 'basic_internal'))

    def __init__(self, *args, **kwargs):
        super(BasicCredentialDirectory, self).__init__(*args, **kwargs)
        self.backend_object = None

    def _ensure_backend(self):
        if not self.backend_object:
            self.backend_object = _create_class_by_name(self.backend_class)(self)

    def verify_credentials(self, principal, credentials):
        self._ensure_backend()

        return self.backend_object.verify_credentials(principal, credentials)

    def create_credentials(self, principal, credentials):
        self._ensure_backend()

        return self.backend_object.create_credentials(principal, credentials)

    def update_credentials(self, principal, old_credentials, new_credentials):
        self._ensure_backend()

        return self.backend_object.update_credentials(principal, old_credentials, new_credentials)

    def reset_credentials(self, super_principal, principal, new_credentials):
        self._ensure_backend()

        return self.backend_object.reset_credentials(super_principal, principal, new_credentials)

    def save(self, *args, **kwargs):
        super(BasicCredentialDirectory, self).save(*args, **kwargs)
        self.backend_object = None

    provided_evidences = models.ManyToManyField(Evidence, related_name='+',
                                                through='BasicCredentialDirectoryProvidedEvidence')


class BasicCredentialDirectoryObjectPermission(AbstractObjectPermission):
    target = models.ForeignKey(BasicCredentialDirectory, related_name='permissions', on_delete=models.CASCADE)


class BasicCredentialDirectoryProvidedEvidence(AbstractReplicatableModel):
    directory = models.ForeignKey(BasicCredentialDirectory, related_name='+', on_delete=models.CASCADE)
    evidence = models.ForeignKey(Evidence, related_name='+', on_delete=models.CASCADE)

    class Meta:
        model_permissions = ()
        verbose_name = 'Evidence Provided by Basic Credential Directory'
        verbose_name_plural = 'Evidences Provided by Basic Credential Directory'

    def __str__(self):
        return ''


class BasicCredentialDirectoryOption(AbstractReplicatableModel):
    directory = models.ForeignKey(BasicCredentialDirectory, related_name='options', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    value = models.TextField()

    class Meta:
        model_permissions = ()

    def __str__(self):
        return '"{0}" ("{1}")'.format(self.name, self.directory.name)


class BasicCredential(AbstractCredential):
    ALGORITHM_NAME_CHOICES = (
        ('pbkdf2', 'pbkdf2'),
        ('bcrypt', 'bcrypt'),
        ('scrypt', 'scrypt'))

    directory = models.ForeignKey(BasicCredentialDirectory, related_name='credentials', on_delete=models.CASCADE)
    algorithm_name = models.CharField(max_length=255, choices=ALGORITHM_NAME_CHOICES, default='pbkdf2')
    algorithm_rounds = models.PositiveIntegerField(default=100000)
    salt = models.BinaryField()
    password_hmac = models.BinaryField()
    force_change = models.BooleanField(default=False)

    class Meta:
        unique_together = [
            ('directory', 'principal')]
        model_permissions = '__all__'
        related_securables = ('principal', 'directory')
        verbose_name = 'Basic Credential'
        verbose_name_plural = 'Basic Credentials'

    def set_password(self, new_password):
        from hashlib import pbkdf2_hmac
        from os import urandom

        self.salt = urandom(64)
        self.password_hmac = pbkdf2_hmac('sha256', new_password.encode('utf-8'), self.salt, self.algorithm_rounds)

    def verify_password(self, password):
        from hashlib import pbkdf2_hmac
        from hmac import compare_digest

        password_hmac = pbkdf2_hmac('sha256', password.encode('utf-8'), self.salt, self.algorithm_rounds)

        return compare_digest(self.password_hmac, password_hmac)

    def __str__(self):
        return '"{0}" ("{1}", "{2}")'.format(
            self.principal,
            type(self)._meta.verbose_name,
            self.directory.name)


class SubnetCredentialDirectory(AbstractCredentialDirectory):
    provided_evidences = models.ManyToManyField(Evidence, related_name='+',
                                                through='SubnetCredentialDirectoryProvidedEvidence')

    class Meta:
        model_permissions = '__all__'
        object_permissions = '__all__'
        verbose_name = 'Subnet Credential Directory'
        verbose_name_plural = 'Subnet Credential Directories'


class SubnetCredentialDirectoryObjectPermission(AbstractObjectPermission):
    target = models.ForeignKey(SubnetCredentialDirectory, related_name='permissions', on_delete=models.CASCADE)


class SubnetCredentialDirectoryProvidedEvidence(AbstractReplicatableModel):
    directory = models.ForeignKey(SubnetCredentialDirectory, related_name='+', on_delete=models.CASCADE)
    evidence = models.ForeignKey(Evidence, related_name='+', on_delete=models.CASCADE)

    class Meta:
        model_permissions = ()
        verbose_name = 'Evidence Provided by Subnet Credential Directory'
        verbose_name_plural = 'Evidences Provided by Subnet Credential Directory'

    def __str__(self):
        return ''


class SubnetCredentialDirectoryOption(AbstractReplicatableModel):
    directory = models.ForeignKey(SubnetCredentialDirectory, related_name='options', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    value = models.TextField()

    class Meta:
        model_permissions = ()

    def __str__(self):
        return '"{0}" ("{1}")'.format(self.name, self.directory.name)


class SubnetCredential(AbstractCredential):
    directory = models.ForeignKey(SubnetCredentialDirectory, related_name='credentials', on_delete=models.CASCADE)
    address = models.GenericIPAddressField()
    network = models.PositiveIntegerField()

    class Meta:
        unique_together = [
            ('directory', 'address')]
        model_permissions = '__all__'
        related_securables = ('principal', 'directory')
        verbose_name = 'Subnet Credential'
        verbose_name_plural = 'Subnet Credentials'

    def __str__(self):
        return '"{0}/{1}" ("{2}", "{3}")'.format(
            self.address,
            self.network,
            type(self)._meta.verbose_name,
            self.directory.name)


class OneTimePasswordCredentialDirectory(AbstractCredentialDirectory):
    provided_evidences = models.ManyToManyField(Evidence, related_name='+',
                                                through='OneTimePasswordCredentialDirectoryProvidedEvidence')

    class Meta:
        model_permissions = '__all__'
        object_permissions = '__all__'
        verbose_name = 'One-Time Password Credential Directory'
        verbose_name_plural = 'One-Time Password Credential Directories'

    @staticmethod
    def get_auth_directory():
        return BasicCredentialDirectory.objects.get(
            code=getattr(settings, 'TALOS_AUTH_DEFAULT_CREDENTIAL_DIRECTORY', 'basic_internal'))

    def __init__(self, *args, **kwargs):
        super(OneTimePasswordCredentialDirectory, self).__init__(*args, **kwargs)
        self.backend_object = None

    def _ensure_backend(self):
        if not self.backend_object:
            self.backend_object = _create_class_by_name(self.backend_class)(self)

    def create_credentials(self, principal, credentials):
        self._ensure_backend()

        return self.backend_object.create_credentials(principal, credentials)

    def verify_credentials(self, principal, credentials):
        self._ensure_backend()

        return self.backend_object.verify_credentials(principal, credentials)

    def update_credentials(self, principal, old_credentials, new_credentials):
        self._ensure_backend()

        return self.backend_object.update_credentials(principal, old_credentials, new_credentials)

    def reset_credentials(self, super_principal, principal, new_credentials):
        self._ensure_backend()

        return self.backend_object.reset_credentials(super_principal, principal, new_credentials)

    def save(self, *args, **kwargs):
        super(OneTimePasswordCredentialDirectory, self).save(*args, **kwargs)
        self.backend_object = None


class OneTimePasswordCredentialDirectoryObjectPermission(AbstractObjectPermission):
    target = models.ForeignKey(OneTimePasswordCredentialDirectory, related_name='permissions', on_delete=models.CASCADE)


class OneTimePasswordCredentialDirectoryProvidedEvidence(AbstractReplicatableModel):
    directory = models.ForeignKey(OneTimePasswordCredentialDirectory, related_name='+', on_delete=models.CASCADE)
    evidence = models.ForeignKey(Evidence, related_name='+', on_delete=models.CASCADE)

    class Meta:
        model_permissions = ()
        verbose_name = 'Evidence Provided by One-Time Password Credential Directory'
        verbose_name_plural = 'Evidences Provided by One-Time Password Credential Directory'

    def __str__(self):
        return ''


class OneTimePasswordCredentialDirectoryOption(AbstractReplicatableModel):
    directory = models.ForeignKey(OneTimePasswordCredentialDirectory, related_name='options', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    value = models.TextField()

    class Meta:
        model_permissions = ()

    def __str__(self):
        return '"{0}" ("{1}")'.format(self.name, self.directory.name)


class OneTimePasswordCredential(AbstractCredential):
    directory = models.ForeignKey(OneTimePasswordCredentialDirectory, related_name='credentials',
                                  on_delete=models.CASCADE)
    salt = models.BinaryField()
    is_activated = models.BooleanField(default=False)

    class Meta:
        unique_together = [
            ('directory', 'principal')]
        model_permissions = '__all__'
        related_securables = ('principal', 'directory')
        verbose_name = 'One-Time Password Credential'
        verbose_name_plural = 'One-Time Password Credentials'

    def __str__(self):
        return str(self.principal)


class TokenCredentialDirectory(AbstractCredentialDirectory):
    provided_evidences = models.ManyToManyField(Evidence, related_name='+',
                                                through='TokenCredentialDirectoryProvidedEvidence')

    class Meta:
        model_permissions = '__all__'
        object_permissions = '__all__'
        verbose_name = 'Token Credential Directory'
        verbose_name_plural = 'Token Credential Directories'


class TokenCredentialDirectoryObjectPermission(AbstractObjectPermission):
    target = models.ForeignKey(TokenCredentialDirectory, related_name='permissions', on_delete=models.CASCADE)


class TokenCredentialDirectoryProvidedEvidence(AbstractReplicatableModel):
    directory = models.ForeignKey(TokenCredentialDirectory, related_name='+', on_delete=models.CASCADE)
    evidence = models.ForeignKey(Evidence, related_name='+', on_delete=models.CASCADE)

    class Meta:
        model_permissions = ()
        verbose_name = 'Evidence Provided by Token Credential Directory'
        verbose_name_plural = 'Evidences Provided by Token Credential Directory'

    def __str__(self):
        return ''


class TokenCredentialDirectoryOption(AbstractReplicatableModel):
    directory = models.ForeignKey(TokenCredentialDirectory, related_name='options', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    value = models.TextField()

    class Meta:
        model_permissions = ()

    def __str__(self):
        return '"{0}" ("{1}")'.format(self.name, self.directory.name)


class TokenCredential(AbstractCredential):
    directory = models.ForeignKey(TokenCredentialDirectory, related_name='credentials', on_delete=models.CASCADE)
    public_value = models.CharField(max_length=255)
    secret_value = models.CharField(max_length=255)

    class Meta:
        unique_together = [
            ('directory', 'principal'),
            ('directory', 'public_value')]
        model_permissions = '__all__'
        related_securables = ('principal', 'directory')
        verbose_name = 'Token Credential'
        verbose_name_plural = 'Token Credentials'

    def __str__(self):
        return self.public_value


class Session(AbstractReplicatableModel):
    previous_session = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE)
    principal = models.ForeignKey('talos.Principal', null=True, blank=True, related_name='sessions',
                                  on_delete=models.CASCADE)
    valid_from = models.DateTimeField(default=_tznow)
    valid_till = models.DateTimeField(default=_tzmax)
    external_id = models.TextField(null=True, blank=True)
    evidences = models.TextField(null=True, blank=True)
    roles = models.TextField(null=True, blank=True)
    privileges = models.TextField(null=True, blank=True)
    model_actions = models.TextField(null=True, blank=True)
    variables = models.TextField(null=True, blank=True)
    remote_address = models.TextField(null=True, blank=True)
    remote_geoname = models.TextField(null=True, blank=True)
    remote_hw_family = models.CharField(null=True, blank=True, max_length=255)
    remote_hw_model = models.CharField(null=True, blank=True, max_length=255)
    remote_os_family = models.CharField(null=True, blank=True, max_length=255)
    remote_os_version = models.CharField(null=True, blank=True, max_length=255)
    remote_ua_family = models.CharField(null=True, blank=True, max_length=255)
    remote_ua_version = models.CharField(null=True, blank=True, max_length=255)

    class Meta:
        model_permissions = ('select', 'delete')
        related_securables = ('principal',)
        verbose_name = 'Session'
        verbose_name_plural = 'Sessions'

    def __str__(self):
        return self.uuid.hex


_basic_credential_directory_cache = None


class PrincipalManager(models.Manager):
    def get_by_natural_key(self, username):
        return super(PrincipalManager, self).get(email=username)


class Principal(AbstractReplicatableModel):
    REQUIRED_FIELDS = []
    USERNAME_FIELD = 'email'

    objects = PrincipalManager()

    brief_name = models.CharField(blank=True, max_length=255)
    full_name = models.CharField(blank=True, max_length=255)
    email = models.EmailField(unique=True, max_length=255)
    phone = models.CharField(blank=True, null=True, unique=True, max_length=255)
    is_active = models.BooleanField(default=True)
    last_login = models.DateTimeField(blank=True, null=True)
    salt = models.BinaryField()
    roles = models.ManyToManyField(Role, through='PrincipalRoleMembership', through_fields=('principal', 'role'))

    class Meta:
        model_permissions = ('__all__')
        object_permissions = ('__all__')
        verbose_name = 'Principal'
        verbose_name_plural = 'Principals'

    def __init__(self, *args, **kwargs):
        from collections import OrderedDict
        super(Principal, self).__init__(*args, **kwargs)
        self._evidences_effective = OrderedDict()
        self._roles_effective = OrderedDict()
        self._privileges_effective = OrderedDict()
        self._model_actions_effective = OrderedDict()

    def _ensure_basic_credential_directory(self):
        global _basic_credential_directory_cache

        if _basic_credential_directory_cache is None:
            _basic_credential_directory_cache = BasicCredentialDirectory.get_auth_directory()

    def _complete_authentication_context(self):
        from collections import defaultdict

        self._model_actions_effective_application = set()
        self._model_actions_effective_model_action = defaultdict(set)

        for code, model_action in self._model_actions_effective.items():
            self._model_actions_effective_application.add(model_action.application)
            self._model_actions_effective_model_action[model_action.model].add(model_action.action)

    def _extract_authentication_context(self):
        from django.core import serializers

        evidences = serializers.serialize(
            'json',
            self._evidences_effective.values(),
            fields=('id', 'uuid', 'code', 'expiration_period'),
            indent=1)
        roles = serializers.serialize(
            'json',
            self._roles_effective.values(),
            fields=('id', 'uuid', 'directory', 'code'),
            indent=1)
        privileges = serializers.serialize(
            'json',
            self._privileges_effective.values(),
            fields=('id', 'uuid', 'code'),
            indent=1)
        model_actions = serializers.serialize(
            'json',
            self._model_actions_effective.values(),
            fields=('id', 'uuid', 'application', 'model', 'action', 'code', 'content_type'),
            indent=1)

        return evidences, roles, privileges, model_actions

    def _inject_authentication_context(self, evidences_json=None, roles_json=None, privileges_json=None,
                                       model_actions_json=None):
        from collections import OrderedDict
        from django.core import serializers

        self._evidences_effective = OrderedDict()
        self._roles_effective = OrderedDict()
        self._privileges_effective = OrderedDict()
        self._model_actions_effective = OrderedDict()

        if evidences_json:
            for evidence in serializers.deserialize('json', evidences_json):
                self._evidences_effective[evidence.object.code] = evidence.object

        if roles_json:
            for role in serializers.deserialize('json', roles_json):
                self._roles_effective[role.object.code] = role.object

        if privileges_json:
            for privilege in serializers.deserialize('json', privileges_json):
                self._privileges_effective[privilege.object.code] = privilege.object

        if model_actions_json:
            for model_action in serializers.deserialize('json', model_actions_json):
                self._model_actions_effective[model_action.object.code] = model_action.object

        self._complete_authentication_context()

    def _load_authentication_context(self, provided_evidences):
        from collections import OrderedDict

        provided_evidence_ids = set(provided_evidence.id for provided_evidence in provided_evidences)
        possible_roles = list(
            membership.role for membership in PrincipalRoleMembership
                .objects
                .filter(principal=self)
                .select_related(
                'role',
                'role__directory')
                .prefetch_related(
                'role__privilege_permissions_effective',
                'role__model_action_permissions_effective',
                'role__directory__required_evidences'))

        self._evidences_effective = OrderedDict()
        self._roles_effective = OrderedDict()
        self._privileges_effective = OrderedDict()
        self._model_actions_effective = OrderedDict()

        for evidence in provided_evidences:
            self._evidences_effective[evidence.code] = evidence

        for possible_role in possible_roles:
            possible_role_directory = possible_role.directory
            possible_role_required_evidences = possible_role_directory.required_evidences.all()
            possible_role_required_evidence_ids = set(
                required_evidence.id for required_evidence in possible_role_required_evidences)

            if possible_role_required_evidence_ids.issubset(provided_evidence_ids):
                self._roles_effective[possible_role.code] = possible_role

                for privilege in possible_role.privilege_permissions_effective.all():
                    self._privileges_effective[privilege.code] = privilege

                for model_action in possible_role.model_action_permissions_effective.all():
                    self._model_actions_effective[model_action.code] = model_action

        self._complete_authentication_context()

    # django.contrib.auth compatibility
    def check_password(self, raw_password):
        self._ensure_basic_credential_directory()

        global _basic_credential_directory_cache

        if not _basic_credential_directory_cache.is_active:
            return False

        now = _tznow()

        try:
            basic_credential = _basic_credential_directory_cache.credentials.get(
                principal=self,
                valid_from__lte=now,
                valid_till__gte=now)

            if basic_credential.verify_password(raw_password):
                return True
        except BasicCredential.DoesNotExist:
            pass

        return False

    # django.contrib.auth compatibility
    def set_password(self, raw_password):
        global _basic_credential_directory_cache

        self._ensure_basic_credential_directory()

        if _basic_credential_directory_cache.is_active:
            try:
                basic_credential = _basic_credential_directory_cache.credentials.get(principal=self)
                basic_credential.set_password(raw_password)
                basic_credential.save()
            except BasicCredential.DoesNotExist:
                basic_credential = BasicCredential()
                basic_credential.principal = self
                basic_credential.directory = _basic_credential_directory_cache
                basic_credential.set_password(raw_password)
                basic_credential.save()

    # django.contrib.auth compatibility
    def has_usable_password(self):
        global _basic_credential_directory_cache

        if _basic_credential_directory_cache is None:
            _basic_credential_directory_cache = BasicCredentialDirectory.get_auth_directory()

        if not _basic_credential_directory_cache.is_active:
            return False

        try:
            _basic_credential_directory_cache.credentials.get(principal=self)

            return True
        except BasicCredential.DoesNotExist:
            pass

        return False

    # django.contrib.auth compatibility
    def has_perm(self, perm, obj=None):
        if not self.is_active:
            return False

        if self.is_superuser:
            return True

        from re import match

        m = match(r'([a-z0-9_]+)\.([a-z0-9]+)_([a-z0-9]+)', perm)
        app_label = m.group(1)
        action_code = m.group(2)
        model_label = m.group(3)

        if action_code == 'add':
            action_code = 'create'
        elif action_code == 'change':
            action_code = 'update'

        action_code = '{0}.{1}.{2}'.format(app_label, model_label, action_code)

        if action_code in self._model_actions_effective:
            return True

        return False

    # django.contrib.auth compatibility
    def has_perms(self, perm_list, obj=None):
        return all(self.has_perm(perm, obj) for perm in perm_list)

    # django.contrib.auth compatibility
    def has_module_perms(self, app_label):
        if not self.is_active:
            return False

        if self.is_superuser:
            return True

        if app_label in self._model_actions_effective_application:
            return True

        return False

    # django.contrib.auth compatibility
    @property
    def is_anonymous(self):
        return (self.id is None) or (self.id == 0)

    # django.contrib.auth compatibility
    @property
    def is_authenticated(self):
        return not ((self.id is None) or (self.id == 0))

    # django.contrib.auth compatibility
    def get_username(self):
        return self.email

    # django.contrib.auth compatibility
    @property
    def is_staff(self):
        return 'django.contrib.admin.web_access' in self._privileges_effective

    # django.contrib.auth compatibility
    @property
    def is_superuser(self):
        return 'django.contrib.talos.all_permissions' in self._privileges_effective

    # django.contrib.auth compatibility
    @property
    def password(self):
        return self.salt.hex()

    # django.contrib.auth compatibility
    @classmethod
    def get_email_field_name(cls):
        return 'email'

    def save(self, *args, **kwargs):
        from os import urandom

        if not self.salt:
            self.salt = urandom(64)

        super(Principal, self).save(*args, **kwargs)

    def __str__(self):
        return self.full_name or self.brief_name or self.email


class PrincipalObjectPermission(AbstractObjectPermission):
    target = models.ForeignKey(Principal, related_name='permissions', on_delete=models.CASCADE)


class ValidationToken(AbstractReplicatableModel):
    principal = models.ForeignKey(Principal, null=True, blank=True, related_name='+', on_delete=models.CASCADE,
                                  editable=False)
    email = models.EmailField(max_length=255, editable=False)
    type = models.CharField(max_length=255, choices=VALIDATION_TOKEN_TYPE_CHOICES, editable=False)
    secret = models.CharField(max_length=64, unique=True, editable=False)
    expires_at = models.DateTimeField(editable=False)
    is_active = models.BooleanField(default=True)

    class Meta:
        model_permissions = '__all__'
        verbose_name = 'Validation Token'
        verbose_name_plural = 'Validation Tokens'

    def save(self, *args, **kwargs):
        from binascii import hexlify
        from datetime import datetime
        from datetime import timedelta
        from os import urandom

        if not self.secret:
            self.secret = hexlify(urandom(32)).decode('ascii').upper()

        if not self.expires_at:
            self.expires_at = _tznow() + timedelta(days=1)

        super(ValidationToken, self).save(*args, **kwargs)

    def __str__(self):
        return self.secret


class PhoneSMSValidationToken(models.Model):
    principal = models.ForeignKey(Principal, null=True, blank=True, related_name='+', on_delete=models.CASCADE,
                                  editable=False)
    secret = models.CharField(max_length=64, unique=True, editable=False)
    phone = models.CharField(max_length=255)
    expires_at = models.DateTimeField(editable=False)
    is_active = models.BooleanField(default=True)
    salt = models.CharField(max_length=64, default='')

    def save(self, *args, **kwargs):
        from binascii import hexlify
        from datetime import timedelta
        from os import urandom
        from .helpers import utils
        from .contrib import twilio

        if not self.secret:
            self.secret = hexlify(urandom(32)).decode('ascii').upper()

        if not self.expires_at:
            self.expires_at = _tznow() + timedelta(minutes=5)

        self.salt = utils.generate_random_number(length=6).encode()

        twilio.send_message(self.phone, '+19144494290',
                            body='Your registraion code is %s' % self.salt.decode())

        super(PhoneSMSValidationToken, self).save(*args, **kwargs)


    def __str__(self):
        return self.secret


class PrincipalProfile(models.Model):
    principal = models.OneToOneField(Principal, related_name='profile', on_delete=models.CASCADE)
    is_secure = models.BooleanField(default=False)

    def __str__(self):
        return str(self.principal) + " is secure" if self.is_secure else "is not secure"
