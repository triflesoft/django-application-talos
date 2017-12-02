from django.apps import AppConfig

from .helpers.admin import AppAdminHelper
from .helpers.discovery import AppDiscoveryHelper
from .helpers.migration import AppMigrationHelper
from .helpers.models import AppModelHelper


_is_initialized = False
admin_helper = AppAdminHelper()
discovery_helper = AppDiscoveryHelper()
migration_helper = AppMigrationHelper()
model_helper = AppModelHelper()


def _initialize(app_configs, messages):
    global _is_initialized
    global admin_helper
    global discovery_helper
    global model_helper

    if not _is_initialized:
        _is_initialized = True
        discovery_helper.discover_permission_models(app_configs, messages)
        model_helper.patch_existing_model_managers(app_configs, messages)
        admin_helper.patch_existing_inline_admin(app_configs, messages)


def _pre_migrate(app_config, **kwargs):
    global migration_helper

    migration_helper.suppress_auth_models(app_config, **kwargs)


def _post_migrate(app_config, **kwargs):
    global migration_helper

    if migration_helper.can_migrate(app_config, **kwargs):
        migration_helper.create_application_dynamic_privileges(app_config, **kwargs)
        migration_helper.create_application_dynamic_permissions(app_config, **kwargs)
        migration_helper.create_standard_objects(app_config, **kwargs)


def _request_started(sender, **kwargs):
    from django.apps import apps
    from django.core.signals import request_started
    from logging import getLogger

    request_started.disconnect(dispatch_uid='ce23b028-1ac1-4e3d-b51a-55e9e6aa2399')

    app_configs = apps.get_app_configs()
    messages = []

    _initialize(app_configs, messages)

    if messages:
        logger = getLogger(__name__)

        for message in messages:
            logger.critical(message)


def _model_checks(app_configs, **kwargs):
    from django.apps import apps

    if app_configs is None:
        app_configs = apps.get_app_configs()

    messages = []

    _initialize(app_configs, messages)

    return messages


class TalosAppConfig(AppConfig):
    name = 'talos'
    verbose_name = 'Talos'
    privileges = [
        ('django.contrib.talos.all_permissions', 'Superuser, has all permissions without explicitly assigning them.'),
        ('django.contrib.admin.web_access', 'Stuff, access admin site.')]

    def ready(self, *args, **kwargs):
        from django.core import checks
        from django.core.signals import request_started
        from django.db.models.signals import post_migrate
        from django.db.models.signals import pre_migrate

        super(TalosAppConfig, self).ready(*args, **kwargs)

        post_migrate.disconnect(dispatch_uid='django.contrib.auth.management.create_permissions')
        pre_migrate.connect(_pre_migrate, dispatch_uid='{0}.{1}'.format(_pre_migrate.__module__, _pre_migrate.__name__))
        post_migrate.connect(_post_migrate, dispatch_uid='{0}.{1}'.format(_post_migrate.__module__, _post_migrate.__name__))
        checks.register(_model_checks, checks.Tags.models)
        request_started.connect(_request_started, dispatch_uid='ce23b028-1ac1-4e3d-b51a-55e9e6aa2399')
