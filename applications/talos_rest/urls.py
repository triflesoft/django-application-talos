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

from talos_rest import constants
from .views import SessionAPIView, EmailChangeRequestAPIView, \
    GoogleAuthenticationActivateRequestView, \
    GoogleAuthenticatorDeleteView, PrincipalSecurityLevelView, \
    GeneratePhoneCodeForAuthorizedUserView, VerifyPhoneCodeForAuthorizedUserView, \
     \
    AddEvidenceView, GeneratePhoneCodeForUnAuthorizedUserView, \
    EmailChangeValidationTokenCheckerAPIView, \
    BasicRegistrationView, PasswordResetRequestView, \
    GoogleAuthenticatorDeleteRequestView, GoogleAuthenticatorActivateConfirmView, \
    EmailResetRequestAPIView, EmailResetValidationTokenCheckerAPIView, \
    \
    EmailChangeSecureAPIView, \
    PhoneChangeValidationTokenCheckerAPIView, PhoneChangeRequestAPIView, PhoneChangeSecureAPIView, \
    PhoneResetRequestAPIView, PhoneResetValidationTokenCheckerAPIView, \
    PhoneResetAPIView, PrincipalSecurityLevelByTokenView, \
    \
    EmailResetAPIView, ProvidedEvidencesView,  \
    PasswordChangeView,  PasswordResetView, LdapSessionAPIView, \
    PasswordResetTokenCheckerAPIView

from rest_framework.documentation import include_docs_urls

PHONE_SMS_CREDENTIAL_DIRECTORY_CODE = 'onetimepassword_internal_phone_sms_authenticator'
GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE = 'onetimepassword_internal_google_authenticator'

urlpatterns = [
    path('docs/', include_docs_urls(title='My API title', public=False,
                                    description='Talos Rest API overview')),

    path('session', SessionAPIView.as_view(), name='talos-rest-sessions'),
    path('ldap/session', LdapSessionAPIView.as_view(), name='talos-rest-ldap-sessions'),

    # Email Change
    path('principal/email/change-request', EmailChangeRequestAPIView.as_view(),
         name='email-change-request'),
    path('email/email-change-token/<slug:secret>',
         EmailChangeValidationTokenCheckerAPIView.as_view(), name='email-change-token-validation'),
    path('principal/email/insecure', EmailChangeSecureAPIView.as_view(),
        {'directory_code' : PHONE_SMS_CREDENTIAL_DIRECTORY_CODE, 'error_code' : constants.PHONE_INVALID_CODE},
         name='email-change-insecure'),
    path('principal/email/secure', EmailChangeSecureAPIView.as_view(),
        {'directory_code' : GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE, 'error_code' : constants.GOOGLE_OTP_INVALID_CODE},
         name='email-change-secure'),

    # Email Reset
    path('principal/email/reset-request', EmailResetRequestAPIView.as_view(),
         name='email-reset-request'),
    path('email/email_reset_token/<slug:secret>', EmailResetValidationTokenCheckerAPIView.as_view(),
         name='email-reset-token-validation'),
    path('principal/reset-email-insecure', EmailResetAPIView.as_view(),
        {'directory_code' : PHONE_SMS_CREDENTIAL_DIRECTORY_CODE, 'error_code' : constants.PHONE_INVALID_CODE},
         name='email-reset-insecure'),
    path('principal/reset-email-secure', EmailResetAPIView.as_view(),
        {'directory_code' : GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE, 'error_code' : constants.GOOGLE_OTP_INVALID_CODE},
         name='email-reset-secure'),

    # Phone Change
    path('principal/phone/change-request', PhoneChangeRequestAPIView.as_view(),
         name='phone-change-request'),
    path('phone/phone_change_token/<slug:secret>',
         PhoneChangeValidationTokenCheckerAPIView.as_view(),
         name='phone-change-token-validation'),
    path('principal/phone/insecure', PhoneChangeSecureAPIView.as_view(),
        {'directory_code' : PHONE_SMS_CREDENTIAL_DIRECTORY_CODE, 'error_code' : constants.SMS_OTP_INVALID_CODE},
         name='phone-change-insecure'),
    path('principal/phone/secure', PhoneChangeSecureAPIView.as_view(),
        {'directory_code' : GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE, 'error_code' : constants.GOOGLE_OTP_INVALID_CODE},
         name='phone-change-secure'),

    # Phone reset
    path('principal/phone/reset-request', PhoneResetRequestAPIView.as_view(),
         name='phone-reset-request'),
    path('phone/phone_reset_token/<slug:secret>',
         PhoneResetValidationTokenCheckerAPIView.as_view(),
         name='phone-reset-token-validation'),
    path('principal/reset-phone-insecure', PhoneResetAPIView.as_view(),
        {'directory_code' : PHONE_SMS_CREDENTIAL_DIRECTORY_CODE, 'error_code' : constants.SMS_OTP_INVALID_CODE},
         name='phone-reset-insecure'),
    path('principal/reset-phone-secure', PhoneResetAPIView.as_view(),
        {'directory_code': GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE, 'error_code': constants.GOOGLE_OTP_INVALID_CODE},
         name='phone-reset-secure'),

    # Password reset
    path('principal/password/reset-request', PasswordResetRequestView.as_view(),
         name='password-reset-request'),

    path('principal/password/reset-token/<slug:secret>', PasswordResetTokenCheckerAPIView.as_view(),
         name='password-reset-validation'),

    path('principal/password/reset/insecure', PasswordResetView.as_view(),
         {'directory_code': PHONE_SMS_CREDENTIAL_DIRECTORY_CODE, 'error_code': constants.PHONE_INVALID_CODE},
         name='password-reset-insecure'),

    path('principal/password/reset/secure', PasswordResetView.as_view(),
         {'directory_code': GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE, 'error_code': constants.GOOGLE_OTP_INVALID_CODE},
         name='password-reset-secure'),

    path('google-authenticator/activate/request', GoogleAuthenticationActivateRequestView.as_view(),
         name='google-authenticator-activate-request'),
    path('google-authenticator/activate/confirm', GoogleAuthenticatorActivateConfirmView.as_view(),
         name='google-authenticator-activate-confirm'),

    path('google-authenticator/delete/request', GoogleAuthenticatorDeleteRequestView.as_view(),
         name='google-authenticator-delete-request'),
    path('google-authenticator/delete/confirm', GoogleAuthenticatorDeleteView.as_view(),
         name='google-authenticator-delete-confirm'),
    path('principal/security-level', PrincipalSecurityLevelView.as_view(),
         name='principal-security-level'),
    path('principal/security-level/token/<slug:secret>',
         PrincipalSecurityLevelByTokenView.as_view(), name='principal-security-level-by-token'),

    path('authorized-phone-verification/generate', GeneratePhoneCodeForAuthorizedUserView.as_view(),
         name='generate-phone-code-for-authorized-user'),

    path('authorized-phone-verification/verify', VerifyPhoneCodeForAuthorizedUserView.as_view(),
         name='verify-phone-code-for-authorized-user'),

    path('evidence/sms', AddEvidenceView.as_view(),
         {'directory_code': PHONE_SMS_CREDENTIAL_DIRECTORY_CODE, 'error_code': constants.SMS_OTP_INVALID_CODE},
         name='add-evidence-sms'),
    path('evidence/google', AddEvidenceView.as_view(),
         {'directory_code': GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE, 'error_code': constants.GOOGLE_OTP_INVALID_CODE},
         name='add-evidence-google'),

    path('phone-verification/generate', GeneratePhoneCodeForUnAuthorizedUserView.as_view(),
         name='generate-phone-code-for-unauthorized-user'),

    # path('phone-verification/verify', VerifyPhoneCodeForUnAuthorizedUserView.as_view(),
    #      name='verify-phone-code-for-unauthorized-user'),

    path('basic-registration', BasicRegistrationView.as_view(), name='basic-registration'),

    path('provided-evidences', ProvidedEvidencesView.as_view(), name='provided-evidences'),

    path('principal/password/insecure', PasswordChangeView.as_view(),
         {'directory_code' : PHONE_SMS_CREDENTIAL_DIRECTORY_CODE, 'error_code' : constants.SMS_OTP_INVALID_CODE},
         name='password-change-insecure'),

    path('principal/password/secure', PasswordChangeView.as_view(),
         {'directory_code' : GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE, 'error_code' : constants.GOOGLE_OTP_INVALID_CODE},
         name='password-change-secure'),

]
