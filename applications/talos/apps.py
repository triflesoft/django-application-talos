from django.apps import AppConfig
from django.core import checks
from django.db.models.signals import class_prepared
from django.db.models.signals import post_migrate
from django.db.models.signals import pre_migrate


from .helpers.admin import AppAdminHelper
from .helpers.discovery import AppDiscoveryHelper
from .helpers.migration import AppMigrationHelper
from .helpers.models import AppModelHelper


discovery_helper = AppDiscoveryHelper()
model_helper = AppModelHelper()
admin_helper = AppAdminHelper()
migration_helper = AppMigrationHelper()

def model_checks(app_configs, **kwargs):
    from django.apps import apps

    messages = []

    if app_configs is None:
        app_configs = apps.get_app_configs()

    discovery_helper.discover_permission_models(app_configs, messages)
    model_helper.patch_existing_model_managers(app_configs, messages)
    admin_helper.patch_existing_inline_admin(app_configs, messages)

    return messages


class TalosAppConfig(AppConfig):
    name = 'talos'
    verbose_name = 'Talos'
    privileges = [
        ('django.contrib.talos.all_permissions', 'Superuser, has all permissions without explicitly assigning them.'),
        ('django.contrib.admin.web_access', 'Stuff, access admin site.')]

    def _pre_migrate(self, app_config, **kwargs):
        migration_helper.suppress_auth_models(app_config, **kwargs)

    def _post_migrate(self, app_config, **kwargs):
        if migration_helper.can_migrate(app_config, **kwargs):
            migration_helper.create_application_dynamic_privileges(app_config, **kwargs)
            migration_helper.create_application_dynamic_permissions(app_config, **kwargs)
            migration_helper.create_standard_objects(app_config, **kwargs)

    def ready(self, *args, **kwargs):
        super(TalosAppConfig, self).ready(*args, **kwargs)

        post_migrate.disconnect(dispatch_uid='django.contrib.auth.management.create_permissions')

        pre_migrate.connect(
            self._pre_migrate,
            dispatch_uid='{0}.{1}'.format(self._pre_migrate.__module__, self._pre_migrate.__name__))

        post_migrate.connect(
            self._post_migrate,
            dispatch_uid='{0}.{1}'.format(self._post_migrate.__module__, self._post_migrate.__name__))

        checks.register(model_checks, checks.Tags.models)
