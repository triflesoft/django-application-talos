from django import forms
from django.contrib import admin
from django.contrib.contenttypes.models import ContentType

from .models import _tznow
from .models import Evidence
from .models import Privilege
from .models import ModelAction
from .models import ObjectAction
from .models import RoleDirectory
from .models import RoleDirectoryOption
from .models import Role
from .models import RoleDirectoryRequiredEvidence
from .models import RolePrivilegePermissionGranted
from .models import RolePrivilegePermissionRevoked
from .models import RoleModelActionPermissionGranted
from .models import RoleModelActionPermissionRevoked
from .models import Principal
from .models import PrincipalRoleMembership
from .models import Realm
from .models import BasicIdentityDirectory
from .models import BasicIdentityDirectoryOption
from .models import BasicIdentity
from .models import BasicCredentialDirectory
from .models import BasicCredentialDirectoryProvidedEvidence
from .models import BasicCredentialDirectoryOption
from .models import BasicCredential
from .models import SubnetCredentialDirectory
from .models import SubnetCredentialDirectoryProvidedEvidence
from .models import SubnetCredentialDirectoryOption
from .models import SubnetCredential
from .models import OneTimePasswordCredentialDirectory
from .models import OneTimePasswordCredentialDirectoryProvidedEvidence
from .models import OneTimePasswordCredentialDirectoryOption
from .models import OneTimePasswordCredential
from .models import TokenCredentialDirectory
from .models import TokenCredentialDirectoryProvidedEvidence
from .models import TokenCredentialDirectoryOption
from .models import TokenCredential
from .models import Session
from .models import ValidationToken
from .models import _hostname


class AbstractReplicatableAdmin(admin.ModelAdmin):
    fieldsets = [
        ('Audit', {
            'classes': ('wide', 'collapse ',),
            'fields': [
                ('id',), ('uuid',),
                ('created_at'), ('created_by',), ('created_on',),
                ('modified_at'), ('modified_by',), ('modified_on')]
        }),
    ]

    readonly_fields = [
        'id', 'uuid',
        'created_at', 'created_by', 'created_on',
        'modified_at', 'modified_by', 'modified_on']

    def get_fieldsets(self, request, obj=None):
        from collections import OrderedDict

        fieldsets = OrderedDict()

        for base_type in type(self).mro():
            base_fieldsets = getattr(base_type, 'fieldsets', None)

            if base_fieldsets is not None:
                for fieldset in base_fieldsets:
                    if not fieldset[0] in fieldsets:
                        fieldsets[fieldset[0]] = fieldset[1]

        return [(key, value) for key, value in fieldsets.items()]

    def save_model(self, request, obj, form, change):
        if obj is not None:
            if not change:
                obj.created_by = request.principal

            obj.modified_by = request.principal
            obj.modified_on = _hostname

        super(AbstractReplicatableAdmin, self).save_model(request, obj, form, change)

    def save_formset(self, request, form, formset, change):
        instances = formset.save(commit=False)

        for obj in instances:
            if obj is not None:
                if not change:
                    obj.created_by = request.principal

                obj.modified_by = request.principal
                obj.modified_on = _hostname

        super(AbstractReplicatableAdmin, self).save_formset(request, form, formset, change)

    class Media:
        css = {'all': ('talos/admin.css',)}


def _formfield_for_foreignkey(self, db_field, request=None, **kwargs):
    field = super(type(self), self).formfield_for_foreignkey(db_field, request, **kwargs)

    if db_field.name == 'permission':
        field.queryset = field.queryset.filter(content_type=ContentType.objects.get_for_model(self._target_model))

    return field


class PermissionAdminMixin(admin.ModelAdmin):
    def __init__(self, *args, **kwargs):
        super(PermissionAdminMixin, self).__init__(*args, **kwargs)

    def get_queryset(self, request):
        model_info = self.model._meta._talos_model_info

        queryset = super(PermissionAdminMixin, self).get_queryset(request)
        queryset = model_info.filter_queryset(queryset, request.principal, 'select')

        return queryset


@admin.register(Evidence)
class EvidenceAdmin(AbstractReplicatableAdmin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('name',), ('code',), ('expiration_period',)]
        }),
    ]
    list_display = ['uuid', 'name', 'code', 'expiration_period']
    ordering = ['code']
    search_fields = ['name', 'code']
    prepopulated_fields = {'code': ('name',)}


@admin.register(Privilege)
class PrivilegeAdmin(AbstractReplicatableAdmin):
    def has_add_permission(self, request):
        return False

    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('name',), ('code',)]
        }),
    ]
    list_display = ['uuid', 'name', 'code']
    ordering = ['code']
    search_fields = ['name', 'code']
    prepopulated_fields = {'code': ('name',)}


class ModelActionContentTypeFilter(admin.SimpleListFilter):
    title = 'Content Type'
    parameter_name = 'content_type'

    def lookups(self, request, model_admin):
        content_types = ContentType.objects.order_by('model').distinct()
        content_types = [content_type for content_type in content_types if hasattr(content_type.model_class()._meta, 'model_actions')]

        return [('{0}.{1}'.format(content_type.app_label, content_type.model), content_type.name) for content_type in content_types]

    def queryset(self, request, queryset):
        if not self.value():
            return queryset

        app_label, model = self.value().split('.')

        return queryset.filter(
            content_type__app_label=app_label,
            content_type__model=model)


class ModelActionForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(ModelActionForm, self).__init__(*args, **kwargs)
        self.fields['content_type'].queryset = ContentType.objects.all().order_by('app_label', 'model')
        self.fields['content_type'].label_from_instance = lambda obj: '{0}.{1}'.format(obj.app_label, obj.model)


@admin.register(ModelAction)
class ModelActionAdmin(AbstractReplicatableAdmin):
    def has_add_permission(self, request):
        return False

    form = ModelActionForm
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('application',), ('model',), ('action',), ('name',), ('code',), ('content_type',)]
        }),
    ]
    list_display = ['uuid', 'application', 'model', 'action', 'name', 'code', 'content_type']
    list_filter = ['application', 'action', ModelActionContentTypeFilter]
    ordering = ['code']
    search_fields = [
        'code',
        'name',
        'content_type__app_label',
        'content_type__model'
    ]
    prepopulated_fields = {'code': ('name',)}


class ObjectActionContentTypeFilter(admin.SimpleListFilter):
    title = 'Content Type'
    parameter_name = 'content_type'

    def lookups(self, request, model_admin):
        content_types = ContentType.objects.order_by('model').distinct()
        content_types = [content_type for content_type in content_types if hasattr(content_type.model_class()._meta, 'object_actions')]

        return [('{0}.{1}'.format(content_type.app_label, content_type.model), content_type.name) for content_type in content_types]

    def queryset(self, request, queryset):
        if not self.value():
            return queryset

        app_label, model = self.value().split('.')

        return queryset.filter(
            content_type__app_label=app_label,
            content_type__model=model)


class ObjectActionForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(ObjectActionForm, self).__init__(*args, **kwargs)
        self.fields['content_type'].queryset = ContentType.objects.all().order_by('app_label', 'model')
        self.fields['content_type'].label_from_instance = lambda obj: '{0}.{1}'.format(obj.app_label, obj.model)


@admin.register(ObjectAction)
class ObjectActionAdmin(AbstractReplicatableAdmin):
    def has_add_permission(self, request):
        return False

    form = ObjectActionForm
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('application',), ('model',), ('action',), ('name',), ('code',), ('content_type',)]
        }),
    ]
    list_display = ['uuid', 'application', 'model', 'action', 'name', 'code', 'content_type']
    list_filter = ['application', 'action', ObjectActionContentTypeFilter]
    ordering = ['code']
    search_fields = [
        'code',
        'name',
        'content_type__app_label',
        'content_type__model'
    ]
    prepopulated_fields = {'code': ('name',)}


class RoleDirectoryOptionInline(admin.TabularInline):
    model = RoleDirectoryOption
    fk_name = 'directory'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class RoleDirectoryRequiredEvidenceInline(admin.TabularInline):
    model = RoleDirectoryRequiredEvidence
    fk_name = 'directory'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


@admin.register(RoleDirectory)
class RoleDirectoryAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('backend_class',), ('is_active',), ('name',), ('code',)]
        }),
    ]
    list_display = ['uuid', 'backend_class', 'is_active', 'name', 'code']
    list_filter = ['is_active']
    ordering = ['name']
    search_fields = [
        'backend_class',
        'name'
    ]
    inlines = [
        RoleDirectoryOptionInline,
        RoleDirectoryRequiredEvidenceInline
    ]
    prepopulated_fields = {'code': ('name',)}


class RolePrivilegePermissionGrantedInline(admin.TabularInline):
    model = RolePrivilegePermissionGranted
    fk_name = 'role'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class RolePrivilegePermissionRevokedInline(admin.TabularInline):
    model = RolePrivilegePermissionRevoked
    fk_name = 'role'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class RoleModelActionPermissionGrantedInline(admin.TabularInline):
    model = RoleModelActionPermissionGranted
    fk_name = 'role'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class RoleModelActionPermissionRevokedInline(admin.TabularInline):
    model = RoleModelActionPermissionRevoked
    fk_name = 'role'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


@admin.register(Role)
class RoleAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('directory',), ('name',), ('code',), ('parent',)]
        }),
    ]
    list_display = ['uuid', 'directory', 'parent', 'code', 'name']
    list_filter = ['directory', 'parent']
    ordering = ['parent__name', 'name']
    search_fields = [
        'name',
        'parent__name'
    ]
    inlines = [
        RolePrivilegePermissionGrantedInline,
        RolePrivilegePermissionRevokedInline,
        RoleModelActionPermissionGrantedInline,
        RoleModelActionPermissionRevokedInline
    ]
    prepopulated_fields = {'code': ('name',)}

    def save_related(self, request, form, formsets, change):
        super(RoleAdmin, self).save_related(request, form, formsets, change)
        form.instance.update_effective_permission_sets()


class PrincipalRoleMembershipInline(admin.TabularInline):
    model = PrincipalRoleMembership
    fk_name = 'principal'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class BasicIdentityInline(admin.TabularInline):
    model = BasicIdentity
    fk_name = 'principal'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class BasicCredentialInlineFormBase(forms.ModelForm):
    def save(self, commit=True):
        model = super(BasicCredentialInlineFormBase, self).save(commit)

        if not commit:
            new_password = self.cleaned_data['new_password']

            if len(new_password) > 0:
                model.set_password(new_password)

        return model

BasicCredentialInlineForm = type(
    'BasicCredentialInlineForm',
    (BasicCredentialInlineFormBase, ),
    {'new_password': forms.CharField(label='New Password', required=False, widget=forms.PasswordInput)})


class BasicCredentialInline(admin.TabularInline):
    model = BasicCredential
    fk_name = 'principal'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')

    def get_formset(self, request, obj=None, **kwargs):
        if request.principal.is_superuser:
            BasicCredentialInline.form = BasicCredentialInlineForm
        else:
            BasicCredentialInline.form = BasicCredentialInlineFormBase

        formset = super(BasicCredentialInline, self).get_formset( request, obj, **kwargs)

        return formset


class SubnetCredentialInline(admin.TabularInline):
    model = SubnetCredential
    fk_name = 'principal'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class OneTimePasswordCredentialInline(admin.TabularInline):
    model = OneTimePasswordCredential
    fk_name = 'principal'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class TokenCredentialInline(admin.TabularInline):
    model = TokenCredential
    fk_name = 'principal'
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


@admin.register(Principal)
class PrincipalAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [
                ('brief_name',),
                ('full_name',),
                ('email',),
                ('phone',),
                ('is_active',)]
        }),
    ]
    list_display = [
        'uuid',
        'brief_name',
        'full_name',
        'email',
        'phone',
        'is_active']
    list_filter = ['is_active']
    ordering = ['full_name']
    search_fields = [
        'brief_name',
        'full_name',
        'email',
        'phone'
    ]
    inlines = [
        PrincipalRoleMembershipInline,
        BasicIdentityInline,
        BasicCredentialInline,
        SubnetCredentialInline,
        OneTimePasswordCredentialInline,
        TokenCredentialInline
    ]


@admin.register(Realm)
class RealmAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('brief_name',), ('full_name',), ('email',)]
        }),
    ]
    list_display = ['uuid', 'brief_name', 'full_name', 'email']
    ordering = ['brief_name']
    search_fields = [
        'brief_name',
        'full_name',
        'email'
    ]


class BasicIdentityDirectoryOptionInline(admin.TabularInline):
    model = BasicIdentityDirectoryOption
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


@admin.register(BasicIdentityDirectory)
class BasicIdentityDirectoryAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('priority',), ('name',), ('code',), ('is_active',), ('realm',), ('backend_class',), ('credential_directory',)]
        }),
    ]
    list_display = ['uuid', 'name', 'code', 'is_active', 'realm', 'backend_class', 'credential_directory']
    list_filter = ['is_active']
    ordering = ['name']
    search_fields = [
        'backend_class',
        'name'
    ]
    inlines = [
        BasicIdentityDirectoryOptionInline
    ]
    prepopulated_fields = {'code': ('name',)}


@admin.register(BasicIdentity)
class BasicIdentityAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [
                ('directory',),
                ('principal',),
                ('username',)]
        }),
    ]
    list_display = [
        'uuid',
        'directory',
        'principal',
        'username']
    list_filter = ['directory']
    ordering = ['principal__email', 'username']
    search_fields = [
        'principal__brief_name',
        'principal__full_name',
        'principal__email',
        'principal__phone',
        'username'
    ]


class BasicCredentialDirectoryOptionInline(admin.TabularInline):
    model = BasicCredentialDirectoryOption
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class BasicCredentialDirectoryProvidedEvidenceInline(admin.TabularInline):
    model = BasicCredentialDirectoryProvidedEvidence
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


@admin.register(BasicCredentialDirectory)
class BasicCredentialDirectoryAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('backend_class',), ('priority',), ('is_active',), ('name',), ('code',)]
        }),
    ]
    list_display = ['uuid', 'backend_class', 'is_active', 'name', 'code']
    list_filter = ['is_active']
    ordering = ['name']
    search_fields = [
        'backend_class',
        'name'
    ]
    inlines = [
        BasicCredentialDirectoryOptionInline,
        BasicCredentialDirectoryProvidedEvidenceInline
    ]
    prepopulated_fields = {'code': ('name',)}


class BasicCredentialForm(forms.ModelForm):
    new_password = forms.CharField(label='New Password', required=False, widget=forms.PasswordInput)

    def save(self, commit=True):
        model = super(BasicCredentialForm, self).save(commit)

        if not commit:
            new_password = self.cleaned_data['new_password']

            if len(new_password) > 0:
                model.set_password(new_password)

        return model

    class Meta:
        model = BasicCredential
        fields = '__all__'


@admin.register(BasicCredential)
class BasicCredentialAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    form = BasicCredentialForm
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [
                ('directory',),
                ('principal',),
                ('valid_from',),
                ('valid_till',),
                ('password',),
                ('algorithm_name',),
                ('algorithm_rounds',),
                ('force_change',),
                ('new_password')]
        }),
    ]
    list_display = [
        'uuid',
        'directory',
        'principal',
        'valid_from',
        'valid_till']
    list_filter = ['directory']
    ordering = ['directory', 'principal']
    readonly_fields = [
        'id', 'uuid',
        'created_at', 'created_by', 'created_on',
        'modified_at', 'modified_by',
        'password']
    search_fields = [
        'principal__brief_name',
        'principal__full_name',
        'principal__email'
        'principal__phone'
    ]

    def password(self, obj):
        return obj.password_hmac.hex()


class SubnetCredentialDirectoryOptionInline(admin.TabularInline):
    model = SubnetCredentialDirectoryOption
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class SubnetCredentialDirectoryProvidedEvidenceInline(admin.TabularInline):
    model = SubnetCredentialDirectoryProvidedEvidence
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


@admin.register(SubnetCredentialDirectory)
class SubnetCredentialDirectoryAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('backend_class',), ('priority',), ('is_active',), ('name',), ('code',)]
        }),
    ]
    list_display = ['uuid', 'backend_class', 'is_active', 'name', 'code']
    list_filter = ['is_active']
    ordering = ['name']
    search_fields = [
        'backend_class',
        'name'
    ]
    inlines = [
        SubnetCredentialDirectoryOptionInline,
        SubnetCredentialDirectoryProvidedEvidenceInline
    ]
    prepopulated_fields = {'code': ('name',)}


@admin.register(SubnetCredential)
class SubnetCredentialAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [
                ('directory',),
                ('principal',),
                ('valid_from',),
                ('valid_till',),
                ('address',),
                ('network',)]
        }),
    ]
    list_display = [
        'uuid',
        'directory',
        'principal',
        'address',
        'valid_from',
        'valid_till']
    list_filter = ['directory']
    ordering = ['address']
    search_fields = [
        'principal__brief_name',
        'principal__full_name',
        'principal__email',
        'principal__phone',
        'address'
    ]


class OneTimePasswordCredentialDirectoryOptionInline(admin.TabularInline):
    model = OneTimePasswordCredentialDirectoryOption
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class OneTimePasswordCredentialDirectoryProvidedEvidenceInline(admin.TabularInline):
    model = OneTimePasswordCredentialDirectoryProvidedEvidence
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


@admin.register(OneTimePasswordCredentialDirectory)
class OneTimePasswordCredentialDirectoryAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('backend_class',), ('priority',), ('is_active',), ('name',), ('code',)]
        }),
    ]
    list_display = ['uuid', 'backend_class', 'is_active', 'name', 'code']
    list_filter = ['is_active']
    ordering = ['name']
    search_fields = [
        'backend_class',
        'name'
    ]
    inlines = [
        OneTimePasswordCredentialDirectoryOptionInline,
        OneTimePasswordCredentialDirectoryProvidedEvidenceInline
    ]
    prepopulated_fields = {'code': ('name',)}


@admin.register(OneTimePasswordCredential)
class OneTimePasswordCredentialAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [
                ('directory',),
                ('principal',),
                ('valid_from',),
                ('valid_till',)]
        }),
    ]
    list_display = [
        'uuid',
        'directory',
        'principal',
        'valid_from',
        'valid_till']
    list_filter = ['directory']
    ordering = ['directory', 'principal']
    search_fields = [
        'principal__brief_name',
        'principal__full_name',
        'principal__email',
        'principal__phone'
    ]


class TokenCredentialDirectoryOptionInline(admin.TabularInline):
    model = TokenCredentialDirectoryOption
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


class TokenCredentialDirectoryProvidedEvidenceInline(admin.TabularInline):
    model = TokenCredentialDirectoryProvidedEvidence
    extra = 0
    readonly_fields = ('created_on', 'modified_on')


@admin.register(TokenCredentialDirectory)
class TokenCredentialDirectoryAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [('backend_class',), ('priority',), ('is_active',), ('name',), ('code',)]
        }),
    ]
    list_display = ['uuid', 'backend_class', 'is_active', 'name', 'code']
    list_filter = ['is_active']
    ordering = ['name']
    search_fields = [
        'backend_class',
        'name'
    ]
    inlines = [
        TokenCredentialDirectoryOptionInline,
        TokenCredentialDirectoryProvidedEvidenceInline
    ]
    prepopulated_fields = {'code': ('name',)}


@admin.register(TokenCredential)
class TokenCredentialAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [
                ('directory',),
                ('principal',),
                ('valid_from',),
                ('valid_till',),
                ('public_value',),
                ('secret_value',)]
        }),
    ]
    list_display = [
        'uuid',
        'directory',
        'principal',
        'public_value',
        'valid_from',
        'valid_till']
    list_filter = ['directory']
    ordering = ['public_value']
    search_fields = [
        'principal__brief_name',
        'principal__full_name',
        'principal__email',
        'principal__phone',
        'public_value'
    ]


def terminate_sessions(modeladmin, request, queryset):
    queryset.update(valid_till=_tznow())

terminate_sessions.short_description = 'Terminate selected Sessions'


@admin.register(Session)
class SessionAdmin(AbstractReplicatableAdmin, PermissionAdminMixin):
    def has_add_permission(self, request):
        return False

    def get_queryset(self, request):
        queryset = super(SessionAdmin, self).get_queryset(request)

        return queryset.exclude(uuid=request.session.uuid)

    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [
                ('previous_session',),
                ('principal',),
                ('valid_from',),
                ('valid_till',),
                ('external_id',),
                ('evidences',),
                ('roles',),
                ('privileges',),
                ('model_permissions',),
                ('variables',),
                ('remote_address',),
                ('remote_geoname',),
                ('remote_hw_family',),
                ('remote_hw_model',),
                ('remote_os_family',),
                ('remote_os_version',),
                ('remote_ua_family',),
                ('remote_ua_version',)]
        }),
    ]
    list_display = [
        'uuid',
        'link_to_previous_session',
        'principal',
        'remote_address', 'remote_geoname',
        'remote_hw_family', 'remote_hw_model',
        'remote_os_family', 'remote_os_version',
        'remote_ua_family', 'remote_ua_version',
        'valid_from', 'valid_till', 'modified_at',
        'external_id']
    list_filter = [
        'principal',
        'valid_from', 'modified_at',
        'remote_geoname',
        'remote_hw_family',
        'remote_hw_model',
        'remote_os_family',
        'remote_os_version',
        'remote_ua_family',
        'remote_ua_version']
    ordering = ['-valid_from']
    readonly_fields = [
        'id', 'uuid',
        'created_at', 'created_by', 'created_on',
        'modified_at', 'modified_by',
        'previous_session',
        'principal',
        'valid_from', 'valid_till',
        'external_id',
        'evidences',
        'roles',
        'privileges',
        'model_actions',
        'variables',
        'remote_address',
        'remote_geoname',
        'remote_hw_family',
        'remote_hw_model',
        'remote_os_family',
        'remote_os_version',
        'remote_ua_family',
        'remote_ua_version']
    search_fields = [
        'principal__full_name',
        'external_id',
        'remote_address', 'remote_geoname',
        'remote_hw_family', 'remote_os_family', 'remote_ua_family'
    ]
    actions = [terminate_sessions]

    def link_to_previous_session(self, obj):
        from django.urls import reverse

        if obj.previous_session:
            link = reverse("admin:talos_session_change", args=[obj.previous_session.id])

            return u'<a href="{0}">{1}</a>'.format(link, obj.previous_session.uuid.hex)

        return ''

    link_to_previous_session.allow_tags = True
    link_to_previous_session.short_description = 'Previous Session'


@admin.register(ValidationToken)
class ValidationTokenAdmin(AbstractReplicatableAdmin):
    def has_add_permission(self, request):
        return False

    fieldsets = [
        ('General',  {
            'classes': ('wide',),
            'fields': [
                ('principal',),
                ('type',),
                ('secret',),
                ('expires_at',),
                ('is_active',)]
        }),
    ]
    list_display = [
        'principal',
        'email',
        'type',
        'expires_at',
        'is_active']
    list_filter = [
        'principal',
        'email',
        'type',
        'expires_at',
        'is_active']
    ordering = ['-expires_at']
    readonly_fields = [
        'id', 'uuid',
        'created_at', 'created_by', 'created_on',
        'modified_at', 'modified_by',
        'principal',
        'type',
        'secret',
        'expires_at',
        'is_active']
    search_fields = [
        'principal__full_name',
        'type'
    ]


from django.contrib.admin.sites import site
from django.contrib.auth.models import Group

site.unregister(Group)
