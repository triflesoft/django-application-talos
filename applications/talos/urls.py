from django.urls import path

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
    path('', IndexView.as_view(), name='talos-index'),
    # METHOD POST domain/v1/principal
    path('principal-registration-request-edit/', PrincipalRegistrationRequestEditView.as_view(), name='talos-principal-registration-request-edit'),
    path('principal-registration-request-done/', PrincipalRegistrationRequestDoneView.as_view(), name='talos-principal-registration-request-done'),
    path('principal-registration-confirm-edit/<slug:secret>', PrincipalRegistrationConfirmEditView.as_view(), name='talos-principal-registration-confirm-edit'),
    path('principal-registration-confirm-done/', PrincipalRegistrationConfirmDoneView.as_view(), name='talos-principal-registration-confirm-done'),

    path('email-change-request-edit/', EmailChangeRequestEditView.as_view(), name='talos-email-change-request-edit'),
    path('email-change-request-done/', EmailChangeRequestDoneView.as_view(), name='talos-email-change-request-done'),
    path('email-change-confirm-edit/<slug:secret>', EmailChangeConfirmEditView.as_view(), name='talos-email-change-confirm-edit'),
    path('email-change-confirm-done/', EmailChangeConfirmDoneView.as_view(), name='talos-email-change-confirm-done'),

    path('logout/', LogoutView.as_view(), name='talos-logout'), #Method DELETE domain/v1/session
    path('basic-login/', BasicLoginView.as_view(), name='talos-basic-login'), # Method POST domain/v1/session
    path('token-login/', TokenLoginView.as_view(), name='talos-token-login'), # Method POST domain/v1/token

    path('basic-password-change-edit/', BasicPasswordChangeConfirmEditView.as_view(), name='talos-basic-password-change-edit'),
    path('basic-password-change-done/', BasicPasswordChangeConfirmDoneView.as_view(), name='talos-basic-password-change-done'),

    path('basic-password-reset-request-edit/', BasicPasswordResetRequestEditView.as_view(), name='talos-basic-password-reset-request-edit'),
    path('basic-password-reset-request-done/', BasicPasswordResetRequestDoneView.as_view(), name='talos-basic-password-reset-request-done'),
    path('basic-password-reset-confirm-edit/<slug:secret>', BasicPasswordResetConfirmEditView.as_view(), name='talos-basic-password-reset-token-edit'),
    path('basic-password-reset-confirm-done/', BasicPasswordResetConfirmDoneView.as_view(), name='talos-basic-password-reset-confirm-done'),
]
