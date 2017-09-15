INVALID_PERMISSION_FORMAT_MESSAGE = (
    'Permissions on {0} are invalid.'
    ' String, or tuple of two elements, or list of two elements expected.')


INVALID_OBJECT_PERMISSION_SET_MESSAGE = (
    'Permissions on {0} are invalid.'
    ' Object permissions, if defined, must be superset of model permissions.')


class DirectActionInfo(object):
    __slots__ = ('action', 'code', 'name')

    def __init__(self, action, code, name):
        self.action = action
        self.code = code
        self.name = name

    def __str__(self):
        return '{0}={1}'.format(self.code, self.name)


class RelatedSecurableInfo(object):
    __slots__ = ('field_name', 'field_obj', 'related_model_info')

    def __init__(self, field_name, field_obj, related_model_info):
        self.field_name = field_name
        self.field_obj = field_obj
        self.related_model_info = related_model_info

    def __str__(self):
        return self.field_name


class QuerySetFilter(object):
    __slots__ = (
        'model_action_code',
        'object_action_code',
        'object_query_action_path',
        'object_query_role_path')

    def __init__(self, model_action_code, object_action_code, object_query_action_path, object_query_role_path):
        self.model_action_code = model_action_code
        self.object_action_code = object_action_code
        self.object_query_action_path = object_query_action_path
        self.object_query_role_path = object_query_role_path


class ModelInfo(object):
    def __init__(self, model):
        self.model = model
        self.model._meta._talos_model_info = self
        self._model_action_infos = None
        self._object_action_infos = None
        self._related_securable_infos = None
        self._queryset_filterset = None

    def _get_action_code(self, action):
        return '{0}.{1}'.format(self.model._meta.label_lower, action)

    def _get_action_own_name(self, action):
        return 'Can {0} "{1}" ({2})'.format(action, self.model._meta.verbose_name, self.model._meta.app_config.label.capitalize())

    def _get_action_property_name(self, action):
        return 'Can modify "{0}" of "{1}" ({2})'.format(action.capitalize(), self.model._meta.verbose_name, self.model._meta.app_config.label.capitalize())

    def _get_direct_action_infos_for_descriptor(self, descriptor, messages):
        from django.core.exceptions import ImproperlyConfigured

        code = None
        name = None

        if type(descriptor) is str:
            code = descriptor
        elif type(descriptor) is tuple:
            if len(descriptor) != 2:
                messages.append(
                    checks.Critical(
                        INVALID_PERMISSION_FORMAT_MESSAGE.format(self.model._meta.label),
                        obj=self._model,
                        id='talos.C020'))

            code = descriptor[0]
            name = descriptor[1]
        elif type(descriptor) is list:
            if len(descriptor) != 2:
                messages.append(
                    checks.Critical(
                        INVALID_PERMISSION_FORMAT_MESSAGE.format(self.model._meta.label),
                        obj=self._model,
                        id='talos.C021'))

            code = descriptor[0]
            name = descriptor[1]

        if code is None:
            messages.append(
                checks.Critical(
                    INVALID_PERMISSION_FORMAT_MESSAGE.format(self.model._meta.label),
                    obj=self._model,
                    id='talos.C022'))

        if code == '__all__':
            return [
                DirectActionInfo('select', self._get_action_code('select'), self._get_action_own_name('select')),
                DirectActionInfo('create', self._get_action_code('create'), self._get_action_own_name('create')),
                DirectActionInfo('update', self._get_action_code('update'), self._get_action_own_name('update')),
                DirectActionInfo('delete', self._get_action_code('delete'), self._get_action_own_name('delete')),
            ]
        elif code.startswith('__'):
            return [
                DirectActionInfo(code, self._get_action_code(code), self._get_action_property_name(code[2:]) if name is None else name)
            ]
        else:
            if code == 'add':
                code = 'create'
            elif code == 'change':
                code = 'update'

            return [
                DirectActionInfo(code, self._get_action_code(code), self._get_action_own_name(code) if name is None else name)
            ]

    def _get_related_securable_infos_for_descriptor(self, descriptor, messages):
        field_name = descriptor
        field_obj = self.model._meta.get_field(field_name)

        if (not field_obj.is_relation) or (not field_obj.many_to_one):
            messages.append(
                checks.Critical(
                    'Field {0} must be of ForeignKey type.'.format(field_name),
                    obj=field_name,
                    id='talos.C030'))

            return []

        related_model_info = field_obj.related_model._meta._talos_model_info

        if not related_model_info.has_actions():
            messages.append(
                checks.Critical(
                    'Related model {0} is not securable.'.format(field_obj.related_model._meta.label),
                    obj=field_obj.related_model,
                    id='talos.C031'))

            return []

        return [
            RelatedSecurableInfo(field_name, field_obj, related_model_info),
        ]

    def _get_model_action_infos(self, messages):
        model_action_infos = []
        model_permissions = getattr(self.model._meta, 'model_permissions', None)
        default_permissions = getattr(self.model._meta, 'default_permissions', None)
        permissions = getattr(self.model._meta, 'permissions', None)

        if model_permissions:
            if type(model_permissions) is str:
                model_action_infos += self._get_direct_action_infos_for_descriptor(model_permissions, messages)
            else:
                for model_action in model_permissions:
                    model_action_infos += self._get_direct_action_infos_for_descriptor(model_action, messages)
        else:
            if default_permissions:
                for default_action in default_permissions:
                    model_action_infos += self._get_direct_action_infos_for_descriptor(default_action, messages)

            if permissions:
                for action in permissions:
                    model_action_infos += self._get_direct_action_infos_for_descriptor(action, messages)

        return model_action_infos

    def _get_object_action_infos(self, messages):
        object_action_infos = []
        object_permissions = getattr(self.model._meta, 'object_permissions', None)

        if object_permissions:
            if type(object_permissions) is str:
                object_action_infos += self._get_direct_action_infos_for_descriptor(object_permissions, messages)
            else:
                for object_action in object_permissions:
                    object_action_infos += self._get_direct_action_infos_for_descriptor(object_action, messages)

        return object_action_infos

    def _get_related_securable_infos(self, messages):
        related_securable_infos = []
        related_securables = getattr(self.model._meta, 'related_securables', None)

        if related_securables:
            if type(related_securables) is str:
                related_securable_infos += self._get_related_securable_infos_for_descriptor(related_securables, messages)
            else:
                for related_securable in related_securables:
                    related_securable_infos += self._get_related_securable_infos_for_descriptor(related_securable, messages)

        return related_securable_infos

    def _update_model_action_infos(self, messages):
        from collections import OrderedDict

        self._model_action_infos = OrderedDict()

        for info in self._get_model_action_infos(messages):
            self._model_action_infos[info.action] = info

    def _update_object_action_infos(self, messages):
        from collections import OrderedDict

        self._object_action_infos = OrderedDict()

        for info in self._get_object_action_infos(messages):
            self._object_action_infos[info.action] = info

    def _update_related_securable_infos(self, messages):
        from collections import OrderedDict

        self._related_securable_infos = OrderedDict()

        for info in self._get_related_securable_infos(messages):
            self._related_securable_infos[info.field_name] = info

    def _ensure_object_action_filters(self):
        if not self._queryset_filterset:
            from django.core.exceptions import ImproperlyConfigured

            if not ((len(self._object_action_infos) == 0) or set(self._object_action_infos.keys()).issuperset(set(self._model_action_infos.keys()))):
                raise ImproperlyConfigured(
                    INVALID_OBJECT_PERMISSION_SET_MESSAGE.format(self.model._meta.label))

            action_keys = set(('select', ))
            action_keys = action_keys.union(self._model_action_infos.keys())
            action_keys = action_keys.union(self._object_action_infos.keys())

            self._queryset_filterset = {}

            for action_key in action_keys:
                queryset_filters = []

                if action_key in self._model_action_infos:
                    has_filter = True

                    if action_key in self._object_action_infos:
                        queryset_filters.append(
                            QuerySetFilter(
                                self._model_action_infos[action_key].code,
                                self._object_action_infos[action_key].code,
                                'permissions__action__code',
                                'permissions__role__in'))
                    else:
                        queryset_filters.append(
                            QuerySetFilter(
                                self._model_action_infos[action_key].code,
                                None,
                                None,
                                None))

                for related_securable_info in self._related_securable_infos.values():
                    related_model_info = related_securable_info.related_model_info

                    if 'select' in related_model_info._model_action_infos:
                        has_filter = True

                        if 'select' in related_model_info._object_action_infos:
                            queryset_filters.append(
                                QuerySetFilter(
                                    related_model_info._model_action_infos[action_key].code,
                                    related_model_info._object_action_infos[action_key].code,
                                    related_securable_info.field_name + '__permissions__action__code',
                                    related_securable_info.field_name + '__permissions__role__in'))
                        else:
                            queryset_filters.append(
                                QuerySetFilter(
                                    related_model_info._model_action_infos[action_key].code,
                                    None,
                                    None,
                                    None))

                if has_filter:
                    self._queryset_filterset[action_key] = queryset_filters

    def has_actions(self):
        if len(self._model_action_infos) > 0 or len(self._object_action_infos) > 0:
            return True

        return len(self._related_securable_infos) > 0

    def has_model_actions(self):
        return len(self._model_action_infos) > 0

    def has_object_actions(self):
        return len(self._object_action_infos) > 0

    def has_related_securables(self):
        return len(self._related_securable_infos) > 0

    def filter_queryset(self, queryset, principal, action):
        from collections import OrderedDict

        if principal.is_superuser:
            return queryset

        self._ensure_object_action_filters()

        queryset_filters = self._queryset_filterset.get('select', None)

        if not queryset_filters:
            return queryset

        new_filter_args = OrderedDict()

        for queryset_filter in queryset_filters:
            if not queryset_filter.model_action_code in principal._model_actions_effective:
                new_filter_args[queryset_filter.object_query_action_path] = queryset_filter.object_action_code
                new_filter_args[queryset_filter.object_query_role_path] = principal._roles_effective.values()

        if len(new_filter_args) > 0:
            queryset = queryset.filter(**new_filter_args)

        return queryset

    @property
    def model_action_infos(self):
        return self._model_action_infos

    @property
    def object_action_infos(self):
        return self._object_action_infos

    @property
    def related_securable_infos(self):
        return self._related_securable_infos


class AppDiscoveryHelper(object):
    def __init__(self):
        self._model_infos = {}

    def discover_permission_models(self, app_configs, messages):
        from django.core import checks
        from django.core.exceptions import FieldDoesNotExist
        from ..models import AbstractObjectPermission

        object_permission_models = {}
        object_secured_models = {}

        for app_config in app_configs:
            for model in app_config.get_models():
                if model._meta.app_config.name in ('django.contrib.auth'):
                    continue

                is_talos_object_permission = getattr(model, '_talos_object_permission', False)

                if is_talos_object_permission:
                    if not model._meta.object_name.endswith('ObjectPermission'):
                        messages.append(
                            checks.Critical(
                                'Model {0} name must end with ObjectPermission.'.format(model._meta.object_name),
                                hint='class SecurableModelObjectPermission(talos.AbstractObjectPermission):',
                                obj=model,
                                id='talos.C001'))
                        continue

                    if not issubclass(model, AbstractObjectPermission):
                        messages.append(
                            checks.Critical(
                                'Model {0} name inherit talos.AbstractObjectPermission.'.format(model._meta.object_name),
                                hint='class SecurableModelObjectPermission(talos.AbstractObjectPermission):',
                                obj=model,
                                id='talos.C002'))
                        continue

                    name_prefix = model._meta.object_name[:-16]

                    try:
                        target_field = model._meta.get_field('target')

                        if (not target_field.is_relation) or (not target_field.many_to_one):
                            messages.append(
                                checks.Critical(
                                    'Model {0} must define field target of type ForeignKey.'.format(model._meta.object_name),
                                    hint='target = models.ForeignKey(SecurableModel, related_name=''permissions'', on_delete=models.CASCADE)',
                                    obj=target_field,
                                    id='talos.C004'))

                        if (target_field.remote_field.related_name != "permissions"):
                            messages.append(
                                checks.Critical(
                                    'Model {0} field target''s related_name must be permissions.'.format(model._meta.object_name),
                                    hint='target = models.ForeignKey(SecurableModel, related_name=''permissions'', on_delete=models.CASCADE)',
                                    obj=target_field,
                                    id='talos.C005'))

                        if target_field.remote_field.model._meta.object_name != name_prefix:
                            messages.append(
                                checks.Critical(
                                    'Model {0} must be named {1}ObjectPermission.'.format(model._meta.object_name, target_field.related_model._meta.object_name),
                                    hint='target = models.ForeignKey(SecurableModel, related_name=''permissions'', on_delete=models.CASCADE)',
                                    obj=target_field.related_model,
                                    id='talos.C006'))
                    except FieldDoesNotExist:
                        messages.append(
                            checks.Critical(
                                'Model {0} must define field target.'.format(model._meta.object_name),
                                hint='target = models.ForeignKey(SecurableModel, related_name=''permissions'', on_delete=models.CASCADE)',
                                obj=model,
                                id='talos.C003'))

                    object_permission_models[name_prefix] = model
                else:
                    model_info = ModelInfo(model)
                    model_info._update_model_action_infos(messages)
                    model_info._update_object_action_infos(messages)
                    model._meta._talos_model_info = model_info
                    self._model_infos[model._meta.label_lower] = model_info

                    if model_info.has_object_actions():
                        object_secured_models[model._meta.object_name] = model

        for app_config in app_configs:
            for model in app_config.get_models():
                model_info = getattr(model._meta, '_talos_model_info', None)

                if model_info:
                    model_info._update_related_securable_infos(messages)

        for secured_model_name, permission_model in object_permission_models.items():
            try:
                secured_model = object_secured_models[secured_model_name]
                secured_model._meta._talos_object_permission_model = permission_model
            except KeyError:
                messages.append(
                    checks.Critical(
                        'Object permission model {0} is defined for model {1}, but is not required.'.format(permission_model._meta.label, secured_model._meta.label),
                        hint='target = models.ForeignKey(SecurableModel, related_name=''permissions'', on_delete=models.CASCADE)',
                        obj=secured_model,
                        id='talos.C010'))

        for secured_model_name, secured_model in object_secured_models.items():
            if not secured_model_name in object_permission_models:
                messages.append(
                    checks.Critical(
                        'Model {0} is missing object permission model {0}ObjectPermission.'.format(secured_model._meta.label),
                        hint='target = models.ForeignKey(SecurableModel, related_name=''permissions'', on_delete=models.CASCADE)',
                        obj=secured_model,
                        id='talos.C011'))

        return messages
