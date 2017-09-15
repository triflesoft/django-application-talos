from django.conf.urls import url

from .views import BasicLoginView
from .views import BasicPasswordChangeConfirmDoneView
from .views import BasicPasswordChangeConfirmEditView
from .views import BasicPasswordResetConfirmDoneView
from .views import BasicPasswordResetConfirmEditView
from .views import BasicPasswordResetRequestDoneView
from .views import BasicPasswordResetRequestEditView
from .views import EmailChangeConfirmDoneView
from .views import EmailChangeConfirmEditView
from .views import EmailChangeRequestDoneView
from .views import EmailChangeRequestEditView
from .views import IndexView
from .views import LogoutView
from .views import PrincipalRegistrationConfirmDoneView
from .views import PrincipalRegistrationConfirmEditView
from .views import PrincipalRegistrationRequestDoneView
from .views import PrincipalRegistrationRequestEditView
from .views import TokenLoginView


auth_url_patterns = [
    url(r'^$', IndexView.as_view(), name='talos-index'),
    url(r'^principal-registration-request-edit/$',
        PrincipalRegistrationRequestEditView.as_view(),
        name='talos-principal-registration-request-edit'),
    url(r'^principal-registration-request-done/$',
        PrincipalRegistrationRequestDoneView.as_view(),
        name='talos-principal-registration-request-done'),
    url(r'^principal-registration-confirm-edit/(?P<secret>[A-Z0-9]+)$',
        PrincipalRegistrationConfirmEditView.as_view(),
        name='talos-principal-registration-confirm-edit'),
    url(r'^principal-registration-confirm-done/$',
        PrincipalRegistrationConfirmDoneView.as_view(),
        name='talos-principal-registration-confirm-done'),

    url(r'^email-change-request-edit/$',
        EmailChangeRequestEditView.as_view(),
        name='talos-email-change-request-edit'),
    url(r'^email-change-request-done/$',
        EmailChangeRequestDoneView.as_view(),
        name='talos-email-change-request-done'),
    url(r'^email-change-confirm-edit/(?P<secret>[A-Z0-9]+)$',
        EmailChangeConfirmEditView.as_view(),
        name='talos-email-change-confirm-edit'),
    url(r'^email-change-confirm-done/$',
        EmailChangeConfirmDoneView.as_view(),
        name='talos-email-change-confirm-done'),

    url(r'^logout/$',
        LogoutView.as_view(),
        name='talos-logout'),

    url(r'^basic-login/$',
        BasicLoginView.as_view(),
        name='talos-basic-login'),

    url(r'^token-login/$',
        TokenLoginView.as_view(),
        name='talos-token-login'),

    url(r'^basic-password-change-edit/$',
        BasicPasswordChangeConfirmEditView.as_view(),
        name='talos-basic-password-change-edit'),
    url(r'^basic-password-change-done/$',
        BasicPasswordChangeConfirmDoneView.as_view(),
        name='talos-basic-password-change-done'),

    url(r'^basic-password-reset-request-edit/$',
        BasicPasswordResetRequestEditView.as_view(),
        name='talos-basic-password-reset-request-edit'),
    url(r'^basic-password-reset-request-done/$',
        BasicPasswordResetRequestDoneView.as_view(),
        name='talos-basic-password-reset-request-done'),
    url(r'^basic-password-reset-confirm-edit/(?P<secret>[A-Z0-9]+)$',
        BasicPasswordResetConfirmEditView.as_view(),
        name='talos-basic-password-reset-token-edit'),
    url(r'^basic-password-reset-confirm-done/$',
        BasicPasswordResetConfirmDoneView.as_view(),
        name='talos-basic-password-reset-confirm-done'),
]
