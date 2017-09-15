class PermissionModelManagerMixin(object):
    def __init__(self, *args, **kwargs):
        super(PermissionModelManagerMixin, self).__init__(*args, **kwargs)

    def for_principal(self, principal, action='select'):
        return self.model._meta._talos_model_info.filter_queryset(self.get_queryset(), principal, action)


class AppModelHelper(object):
    def patch_existing_model_managers(self, app_configs, messages):
        from django.db.models.manager import Manager

        Manager.__bases__ += (PermissionModelManagerMixin,)
