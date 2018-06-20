"""talos_test URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path
from .views import (SessionAPIView, PrincipalRegistrationRequestEditAPIView,
                    PrincipalRegistrationConfirmationAPIView,
                    PrincipalRegistrationTokenValidationAPIView,
                    EmailChangeRequestAPIView,
                    EmailChangeConfirmEditAPIView,
                    GoogleAuthenticationActivateView,
                    GoogleAuthenticatorVerifyView,
                    GoogleAuthenticatorDeleteView,
                    PrincipalSecurityLevelView,
                    GeneratePhoneCodeForAuthorizedUserView,
                    VerifyPhoneCodeForAuthorizedUserView,
                    ChangePasswordInsecureView,
                    ChangePasswordSecureView,
                    AuthorizationUsingSMSView,
                    AuthorizationUsingGoogleAuthenticatorView,
                    GeneratePhoneCodeForUnAuthorizedUserView,
                    VerifyPhoneCodeForUnAuthorizedUserView,
                    BasicRegistrationView,
                    PasswordResetRequestView, PasswordResetConfirmView)


from rest_framework.documentation import include_docs_urls

urlpatterns = [
    path('docs/', include_docs_urls(title='My API title', public=False, description='Talos Rest API overview')),

    path('session', SessionAPIView.as_view(), name='talos-rest-sessions'),

    path('principal/registration_request', PrincipalRegistrationRequestEditAPIView.as_view(),
         name='talos-rest-principal-regisration-request'),
    path('registration_token/<slug:secret>',
         PrincipalRegistrationTokenValidationAPIView.as_view(),
         name='talos-rest-principal-token-validation'),
    path('principal/registration_token/<slug:secret>',
         PrincipalRegistrationConfirmationAPIView.as_view(),
         name='talos-rest-principal-registration-confirm'),

    path('principal/email/request', EmailChangeRequestAPIView.as_view(), name='talos-email-change-request'),
    path('principal/email/email_change_token/<slug:secret>', EmailChangeConfirmEditAPIView.as_view(), name='talos-email-change-confirm'),
    # TODO VERSIONING
    # re_path(r'^(?P<version>(v1|v2))/bookings/$',BasicLoginAPIView.as_view(),name='bookings-list'),

    path('google-authenticator/', GoogleAuthenticationActivateView.as_view(), name='google-authenticator-activate'),
    path('google-authenticator/verify', GoogleAuthenticatorVerifyView.as_view(), name='google-authenticator-verify'),
    path('google-authenticator/delete', GoogleAuthenticatorDeleteView.as_view(), name='google-authenticator-delete'),

    path('principal/security-level', PrincipalSecurityLevelView.as_view(), name='principal-security-level'),

    path('authorized-phone-verification/generate', GeneratePhoneCodeForAuthorizedUserView.as_view(),
         name='generate-phone-code-for-authorized-user'),

    path('authorized-phone-verification/verify', VerifyPhoneCodeForAuthorizedUserView.as_view(),
         name='verify-phone-code-for-authorized-user'),

    path('change-password-unsecure', ChangePasswordInsecureView.as_view(), name='change-password-unsecure'),
    path('change-password-secure', ChangePasswordSecureView.as_view(), name='change-password-secure'),


    path('auth/login-phone', AuthorizationUsingSMSView.as_view(), name='authorization-using-sms'),
    path('auth/login-otp', AuthorizationUsingGoogleAuthenticatorView.as_view(),
         name='authorization-using-google-authenticator'),

    path('phone-verification/generate', GeneratePhoneCodeForUnAuthorizedUserView.as_view(),
         name='generate-phone-code-for-unauthorized-user'),

    path('phone-verification/verify', VerifyPhoneCodeForUnAuthorizedUserView.as_view(),
         name='verify-phone-code-for-unauthorized-user'),

    path('basic-registration', BasicRegistrationView.as_view(), name='basic-registration'),

    path('password-reset-request', PasswordResetRequestView.as_view(), name='password-reset-request'),

    path('password-reset-confirm', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

]
