# Talos


Talos is an alternative authentication, authorization and accounting application. It provides a few improvements over original django.contrib.auth and django-guardian, but is not drop-in replacement though. Migrating to talos or starting a new application should be considered with care.

## Overview

Talos is still work-in-progress and is not generally recommended for production.

Talos provides data required for multipoint master-master application level replication (see AbstractReplicatableModel), but does not include any actual algorithms.

Talos tries to be culture-agnostic, thus Principal field has brief and full names, not first and last ones. It is recommended to create separate UserProfile model customized for actual project needs. For instance some projects may need to store not only given and family names, but also patronymics, matronymics or mononyms. Unlike django.contrib.auth Talos does not enforce and cultural favors.

Some of improvements include:
  * Per model and per object permissions.
  * Integration with django.contrib.admin.
  * Arbitrary privileges.
  * Registration by email address.
  * Various credential type support. Username+password, network address, OTP, client certificates to name a few. Various back-ends to validate these credentials. Separation into principals, identities and credentials.
  * Evidence requirements for role membership.
  * Management commands to manipulate principals, identities,and credentials.
  * List and force log off active sessions.
  * Role hierarchy with permission inheritance.

Authentication scenarios considered in Talos design:
  * User logs in providing username and password
    * Basic credentials are validated against internal database
    * Basic credentials are validated against external LDAP database
    * Basic credentials are validated against external Microsoft Active Directory database
  * User logs in providing username and password, but only from specific IP subnet
    * IPv4 and IPv6 are supported
  * User logs in providing username and password and one-time password
    * One-time password may be proprietary hardware token, Google Authenticator or Microsoft Authenticator
  * User logs in providing username and password and one-time password, but only from specific IP subnet
    * One-time password may be proprietary hardware token, Google Authenticator or Microsoft Authenticator
    * IPv4 and IPv6 are supported
  * Application logs in providing username and password
    * Basic credentials are validated against internal database
    * Basic credentials are validated against external LDAP database
    * Basic credentials are validated against external Microsoft Active Directory database
    * HTTP Authorization header is supported
  * Application logs in from specific IP subnet
    * No other credentials provided
    * IPv4 and IPv6 are supported
  * Application logs in providing access token
    * HTTP Authorization header is supported
  * Application logs in providing access token, but only from specific IP subnet
    * HTTP Authorization header is supported
    * IPv4 and IPv6 are supported

Privilege elevation (sudo, UAC, etc. alike) scenarios considered in Talos design:
  * User elevates privileges providing username and confirming password previously used for authentication
  * User elevates privileges providing username and confirming password previously used for authentication, but only from specific IP subnet
     * IPv4 and IPv6 are supported
  * User elevates privileges providing username and one-time password
    * One-time password may be proprietary hardware token, Google Authenticator or Microsoft Authenticator
  * User elevates privileges providing username, one-time password and confirming password previously used for authentication
    * One-time password may be proprietary hardware token, Google Authenticator or Microsoft Authenticator
  * User elevates privileges providing username, one-time password and confirming password previously used for authentication, but only from specific IP subnet
     * IPv4 and IPv6 are supported
    * One-time password may be proprietary hardware token, Google Authenticator or Microsoft Authenticator

## Quick start

### settings.py
  1. Add "talos" to your INSTALLED_APPS setting. It sould be last application.

    INSTALLED_APPS = [
        ...
        'talos',
    ]

  2. Set user model to talos.Principal

    AUTH_USER_MODEL = 'talos.Principal'

  3. Replace AUTHENTICATION_BACKENDS with talos ones. These are used for django.contrib.admin or other applications dependent directly on django.contrib.auth

    AUTHENTICATION_BACKENDS = (
        'talos.compatibility.auth.AuthBackend',
    )

  4. Fix UserAttributeSimilarityValidator options to validate against talos.Principal fields

    AUTH_PASSWORD_VALIDATORS = [
        {
            'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
            'OPTIONS':
            {
                'user_attributes': ('brief_name', 'full_name', 'email', 'phone'),
            }
        },
        ...
    ]

  5. Disable django.contrib.auth migrations

    MIGRATION_MODULES = {
        'auth': None
    }

  6. Replace session middleware

    MIDDLEWARE = [
        'django.middleware.security.SecurityMiddleware',
        'talos.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        ...
    ]

### urls.py

  1. Add talos URLs to project urlpatterns

    urlpatterns = [
        url(r'^admin/', admin.site.urls),
        url(r'^auth/', include(auth_url_patterns)),
        ...
    ]

### models.py

  1. Specify model permissions in Meta class. Use single name, tuple of names, '__all__' as shortcut for ('select', 'create', 'update', 'delete', ), . Recommeded names are 'select', 'create', 'update', 'delete'. It is highly recommended to always include 'select' if any other permission is specified too. Default is '__all__'

    class Meta:
      model_permissions = '__all__'

  2. Specify object permissions in Meta class. Use single name, tuple of names, '__all__' as shortcut for ('select', 'create', 'update', 'delete', ), . Recommeded names are 'select', 'create', 'update', 'delete'. It is highly recommended to always include 'select' if any other permission is specified too. Default is None

    class Meta:
      object_permissions = '__all__'

  3. Specify related securables in Meta class. Use tuple of ForeignKey field names. To read an object one should have 'select' model or object permission on related object. Default is None

    class Meta:
      related_securables = ('fk_field_name', )

  4. Use for_principal method of model managers to select objects. First argument is talos.Principal instance, for example request.principal. Second argument is permission, 'select' if not specified.

### bash

  1. Creaste new principal

    ./manage.py create_principal --output-status --new-brief-name "Admin" --new-full-name "Administrator" --new-email "administrator@example.com" --new-active

  2. Create new username for existing principal

    ./manage.py create_basic_identity --output-status --principal-email "administrator@example.com" --new-username "administrator"

  3. Create new password for existing principal

    ./manage.py create_basic_credential --output-status --principal-email "administrator@example.com" --new-password "p@$$w0rd"

  4. Add existing principal to existing role

    ./manage.py create_role_membership --output-status --principal-email "administrator@example.com" --role-code "administrators"
