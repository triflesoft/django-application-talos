from django.urls import path

from .views import SessionAPIView, EmailChangeRequestAPIView, \
    GoogleAuthenticationActivateRequestView, \
    GoogleAuthenticatorDeleteView, \
 \
    EmailChangeValidationTokenCheckerAPIView, \
    PasswordResetRequestView, \
    GoogleAuthenticatorDeleteRequestView, GoogleAuthenticatorActivateConfirmView, \
    EmailResetRequestAPIView, EmailResetValidationTokenCheckerAPIView, \
 \
    EmailChangeSecureAPIView, \
    PhoneChangeValidationTokenCheckerAPIView, PhoneChangeRequestAPIView, PhoneChangeSecureAPIView, \
    PhoneResetRequestAPIView, PhoneResetValidationTokenCheckerAPIView, \
    PhoneResetAPIView, \
 \
    EmailResetAPIView, \
    PasswordChangeView, PasswordResetView, \
    PasswordResetTokenCheckerAPIView, SendOTPView, \
    RegistrationRequestView, RegistrationMessageView, EmailActivationRequestView, EmailActivationConfirmationView

PHONE_SMS_CREDENTIAL_DIRECTORY_CODE = 'onetimepassword_internal_phone_sms_authenticator'
GOOGLE_OTP_CREDENTIAL_DIRECTORY_CODE = 'onetimepassword_internal_google_authenticator'

urlpatterns = [

    path('session/', SessionAPIView.as_view(), name='talos-rest-sessions'),

    # Email Change
    path('principal/email/change-request', EmailChangeRequestAPIView.as_view(),
         name='email-change-request'),
    path('email/email-change-token/<slug:secret>',
         EmailChangeValidationTokenCheckerAPIView.as_view(), name='email-change-token-validation'),
    path('principal/email/', EmailChangeSecureAPIView.as_view(), name='email-change-insecure'),


    # Email Reset
    path('principal/email/reset-request', EmailResetRequestAPIView.as_view(),
         name='email-reset-request'),
    path('email/email_reset_token/<slug:secret>', EmailResetValidationTokenCheckerAPIView.as_view(),
         name='email-reset-token-validation'),
    path('principal/reset/email/', EmailResetAPIView.as_view(), name='email-reset-insecure'),


    # Phone Change
    path('principal/phone/change-request', PhoneChangeRequestAPIView.as_view(),
         name='phone-change-request'),
    path('phone/phone_change_token/<slug:secret>',
         PhoneChangeValidationTokenCheckerAPIView.as_view(),
         name='phone-change-token-validation'),
    path('principal/phone/', PhoneChangeSecureAPIView.as_view(), name='phone-change-insecure'),


    # Phone reset
    path('principal/phone/reset-request', PhoneResetRequestAPIView.as_view(),
         name='phone-reset-request'),
    path('phone/phone_reset_token/<slug:secret>',
         PhoneResetValidationTokenCheckerAPIView.as_view(),
         name='phone-reset-token-validation'),
    path('principal/reset/phone/', PhoneResetAPIView.as_view(),
         name='phone-reset-insecure'),

    # Password reset
    path('principal/password/reset-request/', PasswordResetRequestView.as_view(),
         name='password-reset-request'),

    path('principal/password/reset-token/validate/', PasswordResetTokenCheckerAPIView.as_view(),
         name='password-reset-validation'),

    path('principal/password/reset/', PasswordResetView.as_view(),name='password-reset-secure'),

    path('google-authenticator/activate/request', GoogleAuthenticationActivateRequestView.as_view(),
         name='google-authenticator-activate-request'),
    path('google-authenticator/activate/confirm', GoogleAuthenticatorActivateConfirmView.as_view(),
         name='google-authenticator-activate-confirm'),

    path('google-authenticator/delete/request', GoogleAuthenticatorDeleteRequestView.as_view(),
         name='google-authenticator-delete-request'),
    path('google-authenticator/delete/confirm', GoogleAuthenticatorDeleteView.as_view(),
         name='google-authenticator-delete-confirm'),

    path('otp-message/', SendOTPView.as_view(),
         name='send-otp'),

    path('principal/password/', PasswordChangeView.as_view(), name='password-change-insecure'),

    path('registration/', RegistrationRequestView.as_view(), name='registration'),
    path('registration/<slug:id>', RegistrationRequestView.as_view(),name='registration-confirmation'),
    path('registration/<slug:id>/message/', RegistrationMessageView.as_view(), name='registration-message'),

    path('email-activation-message/', EmailActivationRequestView.as_view(), name='email-activation-request'),
    path('email-activation/<slug:secret>/confirmation/', EmailActivationConfirmationView.as_view(), name='email-activation-confirmation'),

]
