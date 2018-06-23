from django.db import DEFAULT_DB_ALIAS


INVALID_PERMISSION_NAME_MESSAGE = (
    'Permissions name "{0}" is not unique.')


def _can_migrate(self, db_alias=DEFAULT_DB_ALIAS, **kwargs):
    return False


class AppMigrationHelper(object):
    def suppress_auth_models(self, app_config, db_alias=DEFAULT_DB_ALIAS, **kwargs):
        if app_config.label == 'auth':
            for model in app_config.get_models():
                model._meta.managed = False
                model._meta.can_migrate = _can_migrate

    def can_migrate(self, app_config, apps, db_alias=DEFAULT_DB_ALIAS, **kwargs):
        from django.db import connections

        connection = connections[db_alias]

        try:
            cursor = connection.cursor()
            table_names = connection.introspection.table_names(cursor)

            return apps.get_model('talos', 'Role')._meta.db_table in table_names
        except:
            return False
        finally:
            cursor.close()

    def create_application_dynamic_privileges(self, app_config, db_alias=DEFAULT_DB_ALIAS, **kwargs):
        from django.apps import apps
        from django.db import router

        privileges = getattr(app_config, 'privileges', None)

        if not privileges:
            return

        try:
            Privilege = apps.get_model('talos', 'Privilege')
        except LookupError:
            return

        if not router.allow_migrate_model(db_alias, Privilege):
            return

        for privilege in privileges:
            Privilege.objects.update_or_create(code=privilege[0], defaults={'name': privilege[1]})

    def create_application_dynamic_permissions(self, app_config, db_alias=DEFAULT_DB_ALIAS, **kwargs):
        from collections import OrderedDict
        from django.apps import apps
        from django.core.exceptions import ImproperlyConfigured
        from django.db import IntegrityError
        from django.db import router

        try:
            ContentType = apps.get_model('contenttypes', 'ContentType')
            ModelAction = apps.get_model('talos', 'ModelAction')
            ObjectAction = apps.get_model('talos', 'ObjectAction')
        except LookupError:
            return

        if not router.allow_migrate_model(db_alias, ModelAction):
            return

        if not router.allow_migrate_model(db_alias, ObjectAction):
            return

        model_action_dict = OrderedDict()
        object_action_dict = OrderedDict()

        for model in app_config.get_models():
            if hasattr(model._meta, '_talos_model_info'):
                model_info = model._meta._talos_model_info

                if model_info.has_actions():
                    content_type = ContentType.objects.db_manager(db_alias).get_for_model(model_info.model)

                    for action_info in model_info.model_action_infos.values():
                        model_action_dict[action_info.code] = ModelAction(
                            application=model._meta.app_config.label,
                            model=model._meta.label_lower,
                            action=action_info.action,
                            code=action_info.code,
                            name=action_info.name,
                            content_type=content_type)

                    for action_info in model_info.object_action_infos.values():
                        object_action_dict[action_info.code] = ObjectAction(
                            application=model._meta.app_config.label,
                            model=model._meta.label_lower,
                            action=action_info.action,
                            code=action_info.code,
                            name=action_info.name,
                            content_type=content_type)

        existing_model_action_codes = list(ModelAction
            .objects
            .using(db_alias)
            .filter(code__in=model_action_dict.keys())
            .values_list('code', flat=True))
        existing_object_action_codes = list(ObjectAction
            .objects
            .using(db_alias)
            .filter(code__in=object_action_dict.keys())
            .values_list('code', flat=True))

        missing_model_action_dict = {code: model_action_dict[code] for code in model_action_dict if code not in existing_model_action_codes}
        missing_object_action_dict = {code: object_action_dict[code] for code in object_action_dict if code not in existing_object_action_codes}

        try:
            ModelAction.objects.using(db_alias).bulk_create(missing_model_action_dict.values())
        except IntegrityError:
            for model_action in missing_model_action_dict.values():
                try:
                    model_action.save()
                except IntegrityError:
                    raise ImproperlyConfigured(
                        INVALID_PERMISSION_NAME_MESSAGE.format(model_action.name))

        try:
            ObjectAction.objects.using(db_alias).bulk_create(missing_object_action_dict.values())
        except IntegrityError:
            for object_action in missing_object_action_dict.values():
                try:
                    object_action.save()
                except IntegrityError:
                    raise ImproperlyConfigured(
                        INVALID_PERMISSION_NAME_MESSAGE.format(object_action.name))

    def create_standard_objects(self, app_config, db_alias=DEFAULT_DB_ALIAS, **kwargs):
        if app_config.label == 'talos':
            from datetime import datetime
            from uuid import UUID
            from ..models import BasicCredentialDirectory
            from ..models import BasicCredentialDirectoryProvidedEvidence
            from ..models import BasicIdentityDirectory
            from ..models import Evidence
            from ..models import OneTimePasswordCredentialDirectory
            from ..models import OneTimePasswordCredentialDirectoryProvidedEvidence
            from ..models import Principal
            from ..models import PrincipalRoleMembership
            from ..models import Privilege
            from ..models import Role
            from ..models import RoleDirectory
            from ..models import RoleDirectoryRequiredEvidence
            from ..models import RolePrivilegePermissionGranted
            from ..models import SubnetCredentialDirectory
            from ..models import SubnetCredentialDirectoryProvidedEvidence
            from ..models import TokenCredentialDirectory
            from ..models import TokenCredentialDirectoryProvidedEvidence

            evidence_authenticated, _ = Evidence.objects.get_or_create(
                code='authenticated',
                defaults={'name': 'Authenticated by any method.'})

            evidence_knowledge_factor, _ = Evidence.objects.get_or_create(
                code='knowledge_factor',
                defaults={'name': 'Authenticated by something a principal knows, for instance password.'})

            evidence_knowledge_factor_password, _ = Evidence.objects.get_or_create(
                code='knowledge_factor_password',
                defaults={'name': 'Authenticated by password.'})

            evidence_knowledge_factor_password_confirmation, _ = Evidence.objects.get_or_create(
                code='knowledge_factor_password_confirmation',
                defaults={'name': 'Authenticated by password confirmation.'})

            evidence_knowledge_factor_access_token, _ = Evidence.objects.get_or_create(
                code='knowledge_factor_access_token',
                defaults={'name': 'Authenticated by access token.'})

            evidence_knowledge_factor_ldap_password , _ = Evidence.objects.get_or_create(
                code='knowledge_factor_ldap_password',
                defaults={'name': 'Authenticated by ldap password.'})

            evidence_ownership_factor, _ = Evidence.objects.get_or_create(
                code='ownership_factor',
                defaults={'name': 'Authenticated by something a principal has, for instance OTP token or phone.'})

            evidence_ownership_factor_phone, _ = Evidence.objects.get_or_create(
                code='ownership_factor_phone',
                defaults={'name': 'Authenticated by phone.'})

            evidence_ownership_factor_otp_token, _ = Evidence.objects.get_or_create(
                code='ownership_factor_otp_token',
                defaults={'name': 'Authenticated by OTP token.'})

            evidence_ownership_factor_google_authenticator, _ = Evidence.objects.get_or_create(
                code='ownership_factor_google_authenticator',
                defaults={'name' : 'Authenticated by Google Authenticator'}
            )

            evidence_inherence_factor, _ = Evidence.objects.get_or_create(
                code='inherence_factor',
                defaults={'name': 'Authenticated by something a principal is, for instance fingerprint or retina.'})

            evidence_inherence_factor_fingerprint, _ = Evidence.objects.get_or_create(
                code='inherence_factor_fingerprint',
                defaults={'name': 'Authenticated by fingerprint.'})

            evidence_inherence_factor_retina, _ = Evidence.objects.get_or_create(
                code='inherence_factor_retina',
                defaults={'name': 'Authenticated by retina.'})

            evidence_location_factor, _ = Evidence.objects.get_or_create(
                code='location_factor',
                defaults={'name': 'Authenticated by somewhere a principal is, for instance IP address.'})

            evidence_location_factor_subnet, _ = Evidence.objects.get_or_create(
                code='location_factor_subnet',
                defaults={'name': 'Authenticated by IP address.'})

            evidence_trust_factor, _ = Evidence.objects.get_or_create(
                code='trust_factor',
                defaults={'name': 'Authenticated by someone who knows a principal, for instance SSL certificate authority.'})

            evidence_trust_factor_ssl_certificate, _ = Evidence.objects.get_or_create(
                code='trust_factor_ssl_certificate',
                defaults={'name': 'Authenticated by SSL certificate authority.'})

            anonymous_role_directory, _ = RoleDirectory.objects.get_or_create(
                code='anonymous_internal',
                defaults={
                    'backend_class': 'talos.directory.role.Internal',
                    'is_active': True,
                    'name': 'Internal Anonymous Role Directory'})

            authenticated_role_directory, _ = RoleDirectory.objects.get_or_create(
                code='authenticated_rinternal',
                defaults={
                    'backend_class': 'talos.directory.role.Internal',
                    'is_active': True,
                    'name': 'Internal Authenticated Role Directory'})

            role_directory_required_evidence_a, _ = RoleDirectoryRequiredEvidence.objects.get_or_create(
                directory=authenticated_role_directory,
                evidence=evidence_authenticated)

            anonymous_role, _ = Role.objects.get_or_create(
                directory=anonymous_role_directory,
                code='anonymous',
                defaults={
                    'id': 0,
                    'uuid': UUID('00000000000000000000000000000000'),
                    'created_at': datetime(1970, 1, 1),
                    'modified_at': datetime(1970, 1, 1),
                    'created_on': 'localhost',
                    'modified_on': 'localhost',
                    'name': 'Anonymous'})

            anonymous_role.update_effective_permission_sets()

            administrators_role, _ = Role.objects.get_or_create(
                directory=authenticated_role_directory,
                code='administrators',
                defaults={'name': 'Administrators'})

            for privilege_code in ('django.contrib.talos.all_permissions', 'django.contrib.admin.web_access'):
                rpg, _ = RolePrivilegePermissionGranted.objects.get_or_create(
                    role=administrators_role,
                    privilege=Privilege.objects.get(code=privilege_code))

            administrators_role.update_effective_permission_sets()

            operators_role, _ = Role.objects.get_or_create(
                directory=authenticated_role_directory,
                code='operators',
                defaults={'name': 'Operators'})

            for privilege_code in ('django.contrib.admin.web_access',):
                rpg, _ = RolePrivilegePermissionGranted.objects.get_or_create(
                    role=operators_role,
                    privilege=Privilege.objects.get(code=privilege_code))

            operators_role.update_effective_permission_sets()

            basic_credential_directory, _ = BasicCredentialDirectory.objects.get_or_create(
                code='basic_internal',
                defaults={
                    'backend_class': 'talos.directory.basic_credential.Internal',
                    'is_active': True,
                    'name': 'Basic Internal Credential Directory'})

            for evidence in (
                    evidence_authenticated,
                    evidence_knowledge_factor,
                    evidence_knowledge_factor_password,
                    evidence_knowledge_factor_password_confirmation):
                BasicCredentialDirectoryProvidedEvidence.objects.get_or_create(directory=basic_credential_directory, evidence=evidence)

            basic_credential_directory_ldap, _ = BasicCredentialDirectory.objects.get_or_create(
                code='ldap',
                defaults={
                    'backend_class': 'talos.directory.basic_credential.Ldap',
                    'is_active': True,
                    'name': 'Basic Ldap Credential Directory'})

            for evidence in (
                    evidence_authenticated,
                    evidence_knowledge_factor,
                    evidence_knowledge_factor_ldap_password):
                BasicCredentialDirectoryProvidedEvidence.objects.get_or_create(directory=basic_credential_directory_ldap, evidence=evidence)


            basic_identity_directory, _ = BasicIdentityDirectory.objects.get_or_create(
                code='basic_internal',
                defaults={
                    'backend_class': 'talos.directory.basic_identity.Internal',
                    'is_active': True,
                    'name': 'Basic Internal Identity Directory',
                    'credential_directory': basic_credential_directory})

            basic_identity_directory_ldap, _ = BasicIdentityDirectory.objects.get_or_create(
                code='ldap',
                defaults={
                    'backend_class': 'talos.directory.basic_identity.Ldap',
                    'is_active': True,
                    'name': 'Basic Ldap Identity Directory',
                    'credential_directory': basic_credential_directory_ldap})

            subnet_credential_directory, _ = SubnetCredentialDirectory.objects.get_or_create(
                code='subnet_internal',
                defaults={
                    'backend_class': 'talos.directory.subnet_credential.Internal',
                    'is_active': True,
                    'name': 'Subnet Internal Credential Directory'})

            for evidence in (
                    evidence_authenticated,
                    evidence_location_factor,
                    evidence_location_factor_subnet):
                SubnetCredentialDirectoryProvidedEvidence.objects.get_or_create(directory=subnet_credential_directory, evidence=evidence)

            access_token_credential_directory, _ = TokenCredentialDirectory.objects.get_or_create(
                code='token_internal_access_token',
                defaults={
                    'backend_class': 'talos.directory.token_credential.InternalSharedSecret',
                    'is_active': True,
                    'name': 'Access Token Internal Credential Directory'})

            for evidence in (
                    evidence_authenticated,
                    evidence_knowledge_factor,
                    evidence_knowledge_factor_access_token):
                TokenCredentialDirectoryProvidedEvidence.objects.get_or_create(directory=access_token_credential_directory, evidence=evidence)

            ssl_certificate_credential_directory, _ = TokenCredentialDirectory.objects.get_or_create(
                code='token_internal_ssl_certificate',
                defaults={
                    'backend_class': 'talos.directory.token_credential.InternalSslCertificate',
                    'is_active': True,
                    'name': 'SSL Certificate Internal Credential Directory'})

            for evidence in (
                    evidence_authenticated,
                    evidence_trust_factor,
                    evidence_trust_factor_ssl_certificate):
                TokenCredentialDirectoryProvidedEvidence.objects.get_or_create(directory=access_token_credential_directory, evidence=evidence)

            phone_sms_credential_directory, _ = OneTimePasswordCredentialDirectory.objects.get_or_create(
                code='onetimepassword_internal_phone_sms_authenticator',
                defaults={
                    'backend_class': 'talos.directory.onetimepassword_credential.InternalPhoneSMS',
                    'is_active': True,
                    'name': 'Phone SMS Internal Credential Directory'})

            for evidence in (
                    evidence_authenticated,
                    evidence_ownership_factor,
                    evidence_ownership_factor_otp_token,
                    evidence_ownership_factor_phone):
                OneTimePasswordCredentialDirectoryProvidedEvidence.objects.get_or_create(directory=phone_sms_credential_directory, evidence=evidence)

            google_authenticator_credential_directory, _ = OneTimePasswordCredentialDirectory.objects.get_or_create(
                code='onetimepassword_internal_google_authenticator',
                defaults={
                    'backend_class': 'talos.directory.onetimepassword_credential.InternalGoogleAuthenticator',
                    'is_active': True,
                    'name': 'Google Authenticator Internal Credential Directory'})

            for evidence in (
                    evidence_authenticated,
                    evidence_ownership_factor,
                    evidence_ownership_factor_otp_token,
                    evidence_ownership_factor_google_authenticator):
                OneTimePasswordCredentialDirectoryProvidedEvidence.objects.get_or_create(directory=google_authenticator_credential_directory, evidence=evidence)

            anonymous_principal, _ = Principal.objects.get_or_create(
                id=0,
                defaults={
                    'id': 0,
                    'uuid': UUID('00000000000000000000000000000000'),
                    'created_at': datetime(1970, 1, 1),
                    'modified_at': datetime(1970, 1, 1),
                    'created_on': 'localhost',
                    'modified_on': 'localhost',
                    'brief_name': 'Anonymous',
                    'full_name': 'Anonymous',
                    'email': 'anonymous@localhost',
                    'is_active': True})

            anonymous_principal_role_memberships = list(PrincipalRoleMembership.objects.filter(principal=anonymous_principal, role=anonymous_role).all())

            if (len(anonymous_principal_role_memberships) != 1) or (anonymous_principal_role_memberships[0].role != anonymous_role):
                PrincipalRoleMembership.objects.filter(principal=anonymous_principal, role=anonymous_role).delete()

                principal_role_membership = PrincipalRoleMembership()
                principal_role_membership.uuid = UUID('00000000000000000000000000000000')
                principal_role_membership.principal = anonymous_principal
                principal_role_membership.role = anonymous_role
                principal_role_membership.save()
