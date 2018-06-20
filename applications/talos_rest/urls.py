
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
                    GoogleAuthenticationActivateRequestView,
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

                    EmailChangeValidationTokenCheckerAPIView,

                    BasicRegistrationView,
                    PasswordResetRequestView, PasswordResetConfirmView,
                    GoogleAuthenticatorDeleteRequestView,
                    GoogleAuthenticatorActivateConfirmView, EmailResetRequestAPIView,

                    EmailResetValidationTokenCheckerAPIView, GoogleAuthenticatorChangeRequestView,
                    GoogleAuthenticatorChangeConfirmView, GoogleAuthenticatorChangeDoneView,
                    EmailChangeInsecureAPIView, EmailChangeSecureAPIView,
                    PrincipalSecurityLevelByTokenView, EmailResetInsecureAPIView,
                    EmailResetSecureAPIView, PhoneResetRequestAPIView)




from rest_framework.documentation import include_docs_urls

urlpatterns = [
    path('docs/', include_docs_urls(title='My API title', public=False, description='Talos Rest API overview')),

    path('session', SessionAPIView.as_view(), name='talos-rest-sessions'),

    # path('principal/registration_request', PrincipalRegistrationRequestEditAPIView.as_view(),
    #      name='talos-rest-principal-regisration-request'),
    # path('registration_token/<slug:secret>',
    #      PrincipalRegistrationTokenValidationAPIView.as_view(),
    #      name='talos-rest-principal-token-validation'),
    # path('principal/registration_token/<slug:secret>',
    #      PrincipalRegistrationConfirmationAPIView.as_view(),
    #      name='talos-rest-principal-registration-confirm'),

    # Email Change
    path('principal/email/change-request', EmailChangeRequestAPIView.as_view(),name='email-change-request'),
    path('email/email-change-token/<slug:secret>',EmailChangeValidationTokenCheckerAPIView.as_view(),name='email-token-validation'),
    path('principal/change-email-insecure', EmailChangeInsecureAPIView.as_view(), name='email-change-insecure'),
    path('principal/change-email-secure', EmailChangeSecureAPIView.as_view(), name='email-change-secure'),

    # Email Reset
    path('principal/email/reset-request', EmailResetRequestAPIView.as_view(), name='email-reset-request'),
    path('email/email_reset_token/<slug:secret>', EmailResetValidationTokenCheckerAPIView.as_view(), name='email-token-validation'),
    path('principal/reset-email-insecure', EmailResetInsecureAPIView.as_view(), name='email-reset-insecure'),
    path('principal/reset-email-secure', EmailResetSecureAPIView.as_view(), name='email-reset-secure'),

    # Phone Change
    path('principal/phone/reset-request', PhoneResetRequestAPIView.as_view(), name='phone-reset-request'),
    # TODO VERSIONING
    # re_path(r'^(?P<version>(v1|v2))/bookings/$',BasicLoginAPIView.as_view(),name='bookings-list'),

    path('google-authenticator/activate/request', GoogleAuthenticationActivateRequestView.as_view(), name='google-authenticator-activate-request'),
    path('google-authenticator/activate/confirm', GoogleAuthenticatorActivateConfirmView.as_view(), name='google-authenticator-activate-confirm'),
    path('google-authenticator/verify', GoogleAuthenticatorVerifyView.as_view(), name='google-authenticator-verify'),
    path('google-authenticator/delete/request', GoogleAuthenticatorDeleteRequestView.as_view(), name='google-authenticator-delete-request'),
    path('google-authenticator/delete/confirm', GoogleAuthenticatorDeleteView.as_view(), name='google-authenticator-delete'),
    path('google-authenticator/change/request', GoogleAuthenticatorChangeRequestView.as_view(), name='google-authenticator-change-request'),
    path('google-authenticator/change/confirm', GoogleAuthenticatorChangeConfirmView.as_view(), name='google-authenticator-change-confirm'),
    path('google-authenticator/change/done', GoogleAuthenticatorChangeDoneView.as_view(), name='google-authneticator-change-done'),

    path('principal/security-level', PrincipalSecurityLevelView.as_view(), name='principal-security-level'),
    path('principal/security-level/token/<slug:secret>', PrincipalSecurityLevelByTokenView.as_view(), name='principal-security-level-by-token'),

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
