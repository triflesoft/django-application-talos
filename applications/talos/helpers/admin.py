def _formfield_for_foreignkey(self, db_field, request=None, **kwargs):
    from django.contrib.contenttypes.models import ContentType

    field = super(type(self), self).formfield_for_foreignkey(db_field, request, **kwargs)

    if db_field.name == 'action':
        field.queryset = field.queryset.filter(content_type=ContentType.objects.get_for_model(self._target_model))

    return field


class AppAdminHelper(object):
    def _create_dynamic_model_inline_admin(self, app_label, label, model, target_model, name, name_plural):
        from django.contrib import admin

        attrs = {
            '__module__': app_label,
            'model': model,
            'fk_name': 'target',
            'verbose_name': name,
            'verbose_name_plural': name_plural}

        model_admin = type(label, (admin.TabularInline,), attrs)
        model_admin.formfield_for_foreignkey = _formfield_for_foreignkey
        model_admin._target_model = target_model

        return model_admin

    def patch_existing_inline_admin(self, app_configs, messages):
        from django.contrib.admin import site

        for app_config in app_configs:
            for model in app_config.get_models():
                if hasattr(model._meta, '_talos_model_info') and hasattr(model._meta, '_talos_object_permission_model'):

                    if model in site._registry:
                        model_admin = site._registry[model]
                        model_info = model._meta._talos_model_info
                        model_admin._talos_model_info = model_info

                        if model_info.has_object_actions():
                            if hasattr(model_admin, 'inlines'):
                                inlines = list(getattr(model_admin, 'inlines'))
                            else:
                                inlines = []

                            inline = self._create_dynamic_model_inline_admin(
                                'talos.admin',
                                '{0}_ObjectPermissionsInline'.format(model.__name__),
                                model._meta._talos_object_permission_model,
                                model,
                                'Permission',
                                'Permissions')

                            inlines.append(inline)

                            setattr(model_admin, 'inlines', inlines)
