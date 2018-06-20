from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from talos_rest import constants

from talos.models import ValidationToken, OneTimePasswordCredential, Principal, BasicIdentity, \
    PrincipalProfile, BasicIdentityDirectory, BasicIdentityDirectoryOption
from talos_rest.serializers import PHONE_SMS_CREDENTIAL_DIRECTORY_CODE


from talos.contrib import sms_sender

def mock_send_message(self, a, b):
    return True

sms_sender.SMSSender.send_message = mock_send_message



class TestUtils(APITestCase):
    full_name = 'bixtrim'
    email = 'at@bixtrim.com'
    password = 'bixtrim_password'
    phone = '+995599439670'

    def __init__(self, *args, **kwargs):
        self.set_values()
        super(TestUtils, self).__init__(*args, **kwargs)

    def set_values(self,
                   full_name=full_name,
                   email=email,
                   password=password,
                   phone=phone):
        self.full_name = full_name
        self.email = email
        self.password = password
        self.phone = phone
        self.principal = None

    def create_user(self):
        from talos.models import Principal
        from talos.models import BasicIdentity
        from talos.models import BasicIdentityDirectory
        from talos.models import PrincipalProfile

        self.principal = Principal.objects.create(full_name=self.full_name,
                                             phone=self.phone,
                                             email=self.email)

        self.principal.set_password(self.password)
        self.principal.save()

        basic_identity = BasicIdentity()
        basic_identity.principal = self.principal
        basic_identity.username = self.email
        basic_identity.directory = BasicIdentityDirectory.objects.get(code='basic_internal')
        basic_identity.save()

        principal_profile  = PrincipalProfile()
        principal_profile.principal = self.principal
        principal_profile.is_secure = False
        principal_profile.save()

    def login(self):
        data = {
            'email': self.email,
            'password': self.password
        }
        url = reverse('talos-rest-sessions')

        response = self.client.post(url, data, format='json')

    def add_evidence_sms(self):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import OneTimePasswordCredential
        from talos.models import Principal
        import pyotp

        add_evidence_sms_url = reverse('add-evidence-sms')

        if self.principal is None:
            raise Exception('Please run create_user() login() before this function')

        otp_directory = OneTimePasswordCredentialDirectory.objects.get(code='onetimepassword_internal_phone_sms_authenticator')
        otp_directory.create_credentials(self.principal, {})

        otp_credential = OneTimePasswordCredential.objects.last()

        self.assertIsNotNone(otp_credential)

        totp = pyotp.TOTP(otp_credential.salt.decode())

        data = {
            'sms_code' : totp.now()
        }

        response = self.client.post(add_evidence_sms_url, data, format='json')

    def generate_sms_code(self,principal):
        from talos.models import  OneTimePasswordCredentialDirectory
        if self.principal is None:
            raise Exception('Please run create_user() login() before this function')

        sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(
            code=PHONE_SMS_CREDENTIAL_DIRECTORY_CODE)
        sms_otp_directory.generate_credentials(principal, {})

    def add_evidence_google(self):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import OneTimePasswordCredential
        import pyotp

        add_evidence_google_url = reverse('add-evidence-google')


        otp_directory = OneTimePasswordCredentialDirectory.objects.get(code='onetimepassword_internal_google_authenticator')
        otp_directory.create_credentials(self.principal, {})

        self.principal.profile.is_secure = True
        self.principal.profile.save()

        otp_credential = OneTimePasswordCredential.objects.last()

        self.assertIsNotNone(otp_credential)

        secret = otp_credential.salt
        totp = pyotp.TOTP(secret)
        google_otp_code = totp.now()

        data = {
            'google_otp_code' : google_otp_code
        }

        response = self.client.post(add_evidence_google_url, data, format='json')


    def assertResponseStatus(self, response, status = status.HTTP_200_OK):
        self.assertEquals(response.status_code, status)
        self.assertEquals(response.data['status'], status)

class TestRegistration(TestUtils):
    url = reverse('basic-registration')

    def test_registration_correct_input(self):

        from talos.models import PhoneSMSValidationToken
        from talos.models import Principal
        from talos.models import BasicIdentity

        phone = '+995599439670'

        phone_validation_token = PhoneSMSValidationToken()
        phone_validation_token.phone = phone
        phone_validation_token.save()

        data = {
            'full_name': 'Giorgi Fafakerashvili',
            'email': 'giorgi.fafa@gmail.com',
            'password': '123456',
            'token': phone_validation_token.secret,
            'code': phone_validation_token.salt.decode(),
            'phone': phone,
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], status.HTTP_201_CREATED)

        principal = Principal.objects.last()
        self.assertIsNotNone(principal)
        self.assertEqual(principal.phone, phone)
        self.assertEqual(principal.full_name, 'Giorgi Fafakerashvili')
        self.assertTrue(principal.check_password('123456'))
        self.assertEqual(principal.email, 'giorgi.fafa@gmail.com')

        basic_identity = BasicIdentity.objects.last()
        self.assertIsNotNone(basic_identity)
        self.assertEqual(basic_identity.principal, principal)
        self.assertEqual(basic_identity.username, principal.email)

    def test_registration_without_phone_sms_token(self):
        data = {
            'full_name': 'Giorgi Fafakerashvili',
            'email': 'giorgi.fafa@gmail.com',
            'password': '123456',
            'token': 'incorrect_token',
            'code': '12345',
            'phone': '+995g599739670',
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(response.data.get('error', False))
        self.assertTrue(response.data.get('error').get('token', False))

    def test_registration_using_same_phone(self):
        self.create_user()

        data = {
            'full_name': self.full_name,
            'email': 'different@bixtrim.com',
            'phone': self.phone,
            'password': self.password
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], status.HTTP_400_BAD_REQUEST)
        self.assertTrue(response.data.get('error', False))
        self.assertEqual(response.data.get('error').get('phone', '')[0], constants.PHONE_USED_CODE)

    def test_registration_using_same_email(self):
        self.create_user()

        data = {
            'full_name': self.full_name,
            'email': self.email,
            'phone': 'phone',
            'password': self.password
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], status.HTTP_400_BAD_REQUEST)
        self.assertTrue(response.data.get('error', False))
        self.assertEqual(response.data.get('error').get('email', '')[0], constants.EMAIL_USED_CODE)

    def test_registration_email_lowering(self):
        from talos.models import PhoneSMSValidationToken
        from talos.models import Principal

        phone_sms_token = PhoneSMSValidationToken()
        phone_sms_token.phone = self.phone
        phone_sms_token.save()

        data = {
            'full_name': self.full_name,
            'email': 'At@bixtrim.com',
            'password': self.password,
            'token': phone_sms_token.secret,
            'code': phone_sms_token.salt,
            'phone': phone_sms_token.phone
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], status.HTTP_201_CREATED)

        principal = Principal.objects.last()

        self.assertEqual(principal.email, 'at@bixtrim.com')

    def test_registration_phone_token(self):
        from talos.models import PhoneSMSValidationToken

        phone_sms_token = PhoneSMSValidationToken()
        phone_sms_token.phone = self.phone
        phone_sms_token.save()

        data = {
            'full_name': self.full_name,
            'email': 'at@bixtrim.com',
            'password': self.password,
            'token': phone_sms_token.secret,
            'code': phone_sms_token.salt,
            'phone': phone_sms_token.phone
        }

        self.assertTrue(phone_sms_token.is_active)

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], status.HTTP_201_CREATED)

        phone_sms_token_updated = PhoneSMSValidationToken.objects.last()
        self.assertFalse(phone_sms_token_updated.is_active)
        self.assertEqual(phone_sms_token_updated.phone, self.phone)
        self.assertEqual(phone_sms_token_updated.secret, phone_sms_token.secret)

        # Use same token again for registration and check errors

        data = {
            'full_name': self.full_name,
            'email': 'different@gmail.com',
            'password': self.password,
            'token': phone_sms_token.secret,
            'code': phone_sms_token.salt,
            'phone': 'phone'
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], status.HTTP_400_BAD_REQUEST)

        self.assertTrue(response.data.get('error', False))
        self.assertEqual(response.data.get('error').get('token', '')[0], constants.TOKEN_INVALID_CODE)


class TestSessions(TestUtils):
    basic_internal_url = reverse('talos-rest-sessions')
    ldap_url = reverse('talos-rest-ldap-sessions')


    def test_user_login(self):
        self.create_user()

        data = {
            'email': self.email,
            'password': self.password
        }

        response = self.client.post(self.basic_internal_url, data, format='json')
        response_data = response.data

        self.assertResponseStatus(response, status.HTTP_200_OK)

        self.assertEqual(response_data['result']['email'], self.email)

    def test_user_login_incorrect_credentials(self):
        self.create_user()

        data = {
            'email': 'test@test.ge',
            'password': 'test'
        }

        response = self.client.post(self.basic_internal_url, data, format='json')
        response_data = response.data

        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)

        self.assertEqual(response_data['error']['email'][0], 'username_invalid')

    def test_user_login_invalid_credentials(self):
        self.create_user()

        data = {}

        response = self.client.post(self.basic_internal_url, data, format='json')
        response_data = response.data

        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)

        self.assertEqual(response_data['error']['email'][0], 'required')
        self.assertEqual(response_data['error']['password'][0], 'required')
        self.assertTrue(response_data.get('details'), False)

    def test_get_session_after_successful_login(self):
        from talos.models import Session

        self.create_user()
        self.login()

        session = Session.objects.last()

        response = self.client.get(self.basic_internal_url)
        response_data = response.data

        self.assertResponseStatus(response, status.HTTP_200_OK)
        self.assertEqual(session.uuid, response_data['result']['session_id'])

    def test_get_session_when_no_login(self):
        response = self.client.get(self.basic_internal_url)

        self.assertResponseStatus(response, status.HTTP_404_NOT_FOUND)
    def test_logout_when_user_isnot_log_in(self):
        response = self.client.delete(self.basic_internal_url)

        self.assertResponseStatus(response, status.HTTP_404_NOT_FOUND)

    def test_logout_when_user_is_log_in(self):
        self.create_user()
        self.login()

        response = self.client.delete(self.basic_internal_url)

        self.assertResponseStatus(response, status.HTTP_200_OK)

    # def test_login_with_ldap(self):
    #     # Create user
    #     self.principal = Principal.objects.create(full_name=self.full_name,
    #                                          phone=self.phone,
    #                                          email=self.email)
    #
    #     self.principal.set_password(self.password)
    #     self.principal.save()
    #
    #     basic_identity = BasicIdentity()
    #     basic_identity.principal = self.principal
    #     basic_identity.username = self.email
    #     basic_identity.directory = BasicIdentityDirectory.objects.get(code='ldap')
    #     basic_identity.save()
    #
    #     principal_profile  = PrincipalProfile()
    #     principal_profile.principal = self.principal
    #     principal_profile.is_secure = False
    #     principal_profile.save()
    #     values = {'host': 'bixtrim.com', 'username': 'test', 'password': 'test', 'port': '123',
    #               'search_base': 'test'}
    #
    #     for key,value in values.items():
    #         basic_identity_directory_option = BasicIdentityDirectoryOption()
    #         setattr(basic_identity_directory_option,'directory_id', '2')
    #         setattr(basic_identity_directory_option, 'name', key)
    #         setattr(basic_identity_directory_option, 'value', value)
    #         basic_identity_directory_option.save()
    #     response = self.client.post(self.ldap_url, data={'email' : self.email, 'password': self.password})
    #     self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
    #     self.assertEquals(response.data.get('error').get('email'),['username_invalid'])

class TestPermissionDeniedPermission(TestUtils):
    url = reverse("email-change-request")

    def test_permission_error_message_when_user_non_secure(self):
        self.create_user()
        self.login()
        response = self.client.post(self.url)

        self.assertResponseStatus(response, status.HTTP_403_FORBIDDEN)
        self.assertListEqual(response.data.get('error'),  ['permission_denied', 'permission_denied', 'permission_denied'])
        self.assertListEqual(response.data.get('details'), ['ownership_factor', 'ownership_factor_otp_token', 'ownership_factor_phone'])

    def test_permission_error_message_when_user_secure(self):
        self.create_user()
        self.principal.profile.is_secure = True
        self.principal.profile.save()
        self.login()

        response = self.client.post(self.url)

        self.assertResponseStatus(response, status.HTTP_403_FORBIDDEN)
        self.assertListEqual(response.data.get('error'),  ['permission_denied', 'permission_denied', 'permission_denied'])
        self.assertListEqual(response.data.get('details'), ['ownership_factor', 'ownership_factor_otp_token', 'ownership_factor_google_authenticator'])

    def test_login_added_correct_evidences(self):
        self.create_user()
        self.login()

        provided_evidences_url = reverse('provided-evidences')


        expected_provided_evidences = ['authenticated',
                                       'knowledge_factor',
                                       'knowledge_factor_password',
                                       'knowledge_factor_password_confirmation']

        response = self.client.get(provided_evidences_url, {}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], status.HTTP_200_OK)

        self.assertListEqual(sorted(expected_provided_evidences),
                             sorted(response.data.get('result').get('provided-evidences', [])))



class GeneratePhoneCodeForUnAuthorizedUser(TestUtils):
    url = reverse('generate-phone-code-for-unauthorized-user')

    def test_generate_phone_code(self):
        from talos.models import PhoneSMSValidationToken

        data = {
            'phone' : self.phone
        }

        response = self.client.post(self.url, data, format='json')



        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], status.HTTP_200_OK)

        phone_sms_token = PhoneSMSValidationToken.objects.last()
        self.assertEqual(phone_sms_token.phone, self.phone)
        self.assertTrue(phone_sms_token.is_active)

        data = {
            'phone' : self.phone
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        phone_sms_token = PhoneSMSValidationToken.objects.last()
        self.assertEqual(phone_sms_token.phone, self.phone)
        self.assertTrue(phone_sms_token.is_active)

        phone_sms_tokens = PhoneSMSValidationToken.objects.all()
        self.assertEqual(phone_sms_tokens.count(), 2)

    def test_generate_invalid_phone(self):
        data = {
            'phone' : 'phone'
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], status.HTTP_400_BAD_REQUEST)

        self.assertTrue(response.data.get('error').get('phone', False))
        self.assertEqual(response.data.get('error').get('phone')[0], constants.PHONE_INVALID_CODE)

    def test_generate_already_used_phone(self):
        self.create_user()

        data = {
            'phone' : self.phone
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], status.HTTP_400_BAD_REQUEST)

        self.assertTrue(response.data.get('error').get('phone', False))
        self.assertEqual(response.data.get('error').get('phone')[0], constants.PHONE_USED_CODE)



class TestVerifyPhoneCodeForUnAuthorizedUser(TestUtils):
    url = reverse('verify-phone-code-for-unauthorized-user')

    def test_verify_phone_code_for_unauthorized(self):
        from talos.models import PhoneSMSValidationToken

        phone_sms_token = PhoneSMSValidationToken()
        phone_sms_token.phone = self.phone
        phone_sms_token.save()

        data = {
            'phone' : self.phone,
            'code' : phone_sms_token.salt
        }


        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], status.HTTP_200_OK)

        self.assertTrue(response.data.get('result').get('token', False))
        self.assertEqual(response.data.get('result').get('token'), phone_sms_token.secret)


    def test_verify_phone_invalid_input(self):
        from talos.models import PhoneSMSValidationToken

        phone_sms_token = PhoneSMSValidationToken()
        phone_sms_token.phone = self.phone
        phone_sms_token.save()

        data = {
            'phone' : self.phone,
            'code' : 'aaaa'
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], status.HTTP_400_BAD_REQUEST)

        self.assertTrue(response.data.get('error').get('code', False))
        self.assertEqual(response.data.get('error').get('code')[0], constants.SMS_OTP_INVALID_CODE)

        data = {
            'phone' : 'phone_valid',
            'code' : phone_sms_token.salt
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], status.HTTP_400_BAD_REQUEST)

        self.assertTrue(response.data.get('error').get('phone', False))
        self.assertEqual(response.data.get('error').get('phone')[0], constants.PHONE_INVALID_CODE)


    def test_verify_already_used_token(self):
        from talos.models import PhoneSMSValidationToken

        phone_sms_token = PhoneSMSValidationToken()
        phone_sms_token.phone = self.phone
        phone_sms_token.is_active = False
        phone_sms_token.save()

        data = {
            'phone' : self.phone,
            'code' : phone_sms_token.salt
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], status.HTTP_400_BAD_REQUEST)

        self.assertTrue(response.data.get('error').get('phone', False))
        self.assertEqual(response.data.get('error').get('phone')[0], constants.PHONE_INVALID_CODE)

        self.assertTrue(response.data.get('error').get('code', False))
        self.assertEqual(response.data.get('error').get('code')[0], constants.SMS_OTP_INVALID_CODE)


class TestEmailChange(TestUtils):
    email_change_request_url  = reverse("email-change-request")
    email_change_insecure_url = reverse("email-change-insecure")
    email_change_secure_url = reverse("email-change-secure")

    def test_get_method_on_email_change(self):

        response = self.client.get(self.email_change_request_url)
        self.assertResponseStatus(response, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEquals(response.data.get('error'), 'method_not_allowed')


    def test_email_change_request_when_no_data(self):
        self.create_user()
        self.login()
        self.add_evidence_sms()

        data = {}
        response = self.client.post(self.email_change_request_url,data)
        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('new_email'),['required'])

    def test_email_change_request_when_invalid_email(self):
        self.create_user()
        self.login()
        self.add_evidence_sms()

        data = {'new_email' : 'asd'}
        response = self.client.post(self.email_change_request_url, data)
        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('new_email'), ['email_invalid'])

    def test_email_change_request_when_passed_used_email(self):
        self.create_user()
        self.login()
        self.add_evidence_sms()

        data = {'new_email' : self.email}
        response = self.client.post(self.email_change_request_url, data)
        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('new_email'), ['email_used'])

    def test_email_change_request_when_success(self):
        from talos.models import ValidationToken
        from django.utils import timezone
        now = timezone.now()
        self.create_user()
        self.login()
        self.add_evidence_sms()

        data = {'new_email' : 'correct@bixtrim.ge'}
        response = self.client.post(self.email_change_request_url, data)

        self.assertResponseStatus(response)
        self.assertEquals(response.data.get('result').get('new_email'),data['new_email'])
        self.assertEquals(ValidationToken.objects.count(),1)
        validation_token = ValidationToken.objects.last()
        self.assertEquals(validation_token.type,'email_change')
        self.assertEquals(validation_token.is_active,True)
        self.assertEquals(validation_token.principal_id, 1)
        self.assertEquals(validation_token.identifier,'email')
        self.assertGreaterEqual(validation_token.expires_at, now)

    def test_email_change_token_validation_when_invalid_token(self):
        url = reverse("email-change-token-validation", kwargs={'secret': '1234'})
        self.create_user()
        self.login()
        self.add_evidence_sms()

        response = self.client.get(url)

        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('secret'),['token_invalid'])

    def test_email_change_token_validation_when_success(self):
        self.create_user()
        self.login()
        self.add_evidence_sms()

        validation_token = ValidationToken.objects.create(identifier = 'email',
                                                          identifier_value=self.email,
                                                          principal=self.principal,
                                                          type='email_change',
                                                          )
        url = reverse("email-change-token-validation", kwargs={'secret': validation_token.secret})
        response = self.client.get(url)

        self.assertResponseStatus(response)
        self.assertEqual(response.data.get('result').get('secret'), None)

    def test_email_change_token_validation_when_not_active_token(self):
        self.create_user()
        self.login()
        self.add_evidence_sms()

        validation_token = ValidationToken.objects.create(identifier = 'email',
                                                          identifier_value=self.email,
                                                          principal=self.principal,
                                                          type='email_change',
                                                          )
        validation_token.is_active = False
        validation_token.save()

        url = reverse("email-change-token-validation", kwargs={'secret': validation_token.secret})
        response = self.client.get(url)

        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('secret'),['token_invalid'])

    def test_email_change_token_validation_when_different_token_type(self):
        self.create_user()
        self.login()
        self.add_evidence_sms()

        validation_token = ValidationToken.objects.create(identifier = 'email',
                                                          identifier_value=self.email,
                                                          principal=self.principal,
                                                          type='email_change',
                                                          )
        validation_token.type = 'different'
        validation_token.save()

        url = reverse("email-change-token-validation", kwargs={'secret': validation_token.secret})
        response = self.client.get(url)

        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('secret'),['token_invalid'])

    def test_change_email_insecure_when_no_session(self):
        self.create_user()
        response = self.client.put(self.email_change_insecure_url)
        self.assertResponseStatus(response,status.HTTP_403_FORBIDDEN)
        self.assertListEqual(response.data.get('error'),
                             ['permission_denied', 'permission_denied', 'permission_denied',
                              'permission_denied', 'permission_denied'])
        self.assertListEqual(response.data.get('details'),
                             ['authenticated', 'knowledge_factor', 'knowledge_factor_password',
                              'ownership_factor', 'ownership_factor_otp_token'])

    def test_change_email_insecure_when_no_sms_evidence(self):
        self.create_user()
        self.login()
        response = self.client.put(self.email_change_insecure_url)
        self.assertResponseStatus(response,status.HTTP_403_FORBIDDEN)
        self.assertListEqual(response.data.get('error'),
                             ['permission_denied', 'permission_denied', 'permission_denied'])
        self.assertListEqual(response.data.get('details'),
                             ['ownership_factor', 'ownership_factor_otp_token',
                              'ownership_factor_phone'])

    def test_change_email_when_no_data(self):
        self.create_user()
        self.login()
        self.add_evidence_sms()
        response = self.client.put(self.email_change_insecure_url)
        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(response.data.get('error'),
                             {'sms_code': ['required'], 'password': ['required'],
                              'secret': ['required']})
        self.assertDictEqual(response.data.get('details'),
                             {'sms_code': ['This field is required.'],
                              'password': ['This field is required.'],
                              'secret': ['This field is required.']})

    def test_change_email_when_wrong_secret(self):
        from talos.models import OneTimePasswordCredential

        self.create_user()
        self.login()
        self.add_evidence_sms()
        self.generate_sms_code(self.principal)

        code = (OneTimePasswordCredential.objects.last())
        response = self.client.put(self.email_change_insecure_url, data= {'sms_code' : code.salt.decode(),
                                                                          'password' : self.password,
                                                                          'secret' : '1234'})
        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('secret'), ['token_invalid'])
        self.assertListEqual(response.data.get('details').get('secret'), ['Token is not valid.'])

    def test_change_email_when_wrong_sms(self):

        self.create_user()
        self.login()
        self.add_evidence_sms()
        self.generate_sms_code(self.principal)

        validation_token = ValidationToken.objects.create(identifier = 'email',
                                                          identifier_value=self.email,
                                                          principal=self.principal,
                                                          type='email_change',)

        response = self.client.put(self.email_change_insecure_url, data= {'sms_code': '1234',
                                                                          'password': self.password,
                                                                          'secret': validation_token.secret})
        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('sms_code'), ['sms_otp_invalid'])
        self.assertListEqual(response.data.get('details').get('sms_code'), ['OTP code is incorrect'])

    def test_change_email_when_wrong_password(self):
        import pyotp
        self.create_user()
        self.login()
        self.add_evidence_sms()
        self.generate_sms_code(self.principal)

        validation_token = ValidationToken.objects.create(identifier = 'email',
                                                          identifier_value=self.email,
                                                          principal=self.principal,
                                                          type='email_change',)
        code = (OneTimePasswordCredential.objects.last())

        totp = pyotp.TOTP(code.salt.decode())

        data = {'sms_code': totp.now(),
                'password': '1234',
                 'secret': validation_token.secret}

        response = self.client.put(self.email_change_insecure_url, data=data)

        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('password'),['password_invalid'])
        self.assertListEqual(response.data.get('details').get('password'), ['Password is incorrect'])

    def test_change_email_when_success(self):
        import pyotp
        self.create_user()
        self.login()
        self.add_evidence_sms()
        self.generate_sms_code(self.principal)

        email_to_change = "change@bixtim.ge"
        validation_token = ValidationToken.objects.create(identifier = 'email',
                                                          identifier_value=email_to_change,
                                                          principal=self.principal,
                                                          type='email_change',)
        code = (OneTimePasswordCredential.objects.last())

        totp = pyotp.TOTP(code.salt.decode())

        data = {
            'sms_code': totp.now(),
            'password': self.password,
            'secret': validation_token.secret
        }

        response = self.client.put(self.email_change_insecure_url, data=data)

        changed_pricipal = Principal.objects.last()

        self.assertResponseStatus(response)
        self.assertEquals(changed_pricipal.email, email_to_change)

class TestAddSMSEvidence(TestUtils):
    url = reverse('add-evidence-sms')

    def test_add_sms_evidence(self):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import OneTimePasswordCredential
        from talos.models import Principal
        import pyotp

        self.create_user()
        self.login()

        principal = Principal.objects.last()
        otp_diretory = OneTimePasswordCredentialDirectory.objects.get(code='onetimepassword_internal_phone_sms_authenticator')

        otp_diretory.create_credentials(principal, {})

        self.assertEqual(OneTimePasswordCredential.objects.all().count(), 1)

        otp_credential = OneTimePasswordCredential.objects.last()

        totp = pyotp.TOTP(otp_credential.salt.decode())

        data = {
            'sms_code' : totp.now()
        }

        response = self.client.post(self.url, data, format='json')


        self.assertResponseStatus(response, status.HTTP_200_OK)

        # Test on incorrect input

        data = {
            'sms_code' : 'aaaa'
        }

        response = self.client.post(self.url, data, format='json')

        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(response.data.get('error').get('sms_code', False))
        self.assertEqual(response.data.get('error').get('sms_code')[0], constants.SMS_OTP_INVALID_CODE)


    def test_added_provided_evidences(self):
        self.create_user()
        self.login()

        provided_evidences_url = reverse('provided-evidences')

        response = self.client.get(provided_evidences_url, {}, format='json')

        expected_provided_evidences = ['authenticated',
                                       'knowledge_factor',
                                       'knowledge_factor_password',
                                       'knowledge_factor_password_confirmation']

        self.assertResponseStatus(response, status.HTTP_200_OK)
        self.assertListEqual(sorted(response.data.get('result').get('provided-evidences')),
                             sorted(expected_provided_evidences))


        expected_provided_evidences = ['authenticated',
                                       'knowledge_factor',
                                       'knowledge_factor_password',
                                       'knowledge_factor_password_confirmation',
                                       'ownership_factor_otp_token',
                                       'ownership_factor_phone',
                                       'ownership_factor']
        self.add_evidence_sms()


        response = self.client.get(provided_evidences_url, {}, format='json')

        response_list = list(response.data.get('result').get('provided-evidences'))

        self.assertListEqual(sorted(response_list),sorted(expected_provided_evidences))


class TestAddGoogleEvidence(TestUtils):
    url = reverse('add-evidence-google')

    def test_add_evidence_google(self):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import OneTimePasswordCredential
        from talos.models import Principal
        import pyotp

        self.create_user()
        self.login()

        principal = Principal.objects.last()
        otp_diretory = OneTimePasswordCredentialDirectory.objects.get(
            code='onetimepassword_internal_google_authenticator')

        otp_diretory.create_credentials(principal, {})

        self.assertEqual(OneTimePasswordCredential.objects.all().count(), 1)

        otp_credential = OneTimePasswordCredential.objects.last()

        secret = otp_credential.salt

        totp = pyotp.TOTP(secret)
        code = totp.now()

        data = {
            'google_otp_code': code
        }

        response = self.client.post(self.url, data, format='json')


        self.assertResponseStatus(response, status.HTTP_200_OK)

        # Try incorrect data

        data = {
            'google_otp_code' : 'aaaa'
        }

        response = self.client.post(self.url, data, format='json')

        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(response.data.get('error').get('google_otp_code', False))
        self.assertEqual(response.data.get('error').get('google_otp_code')[0], constants.GOOGLE_OTP_INVALID_CODE)


    def test_add_evidence_google_check_provided_evidences(self):
        self.create_user()
        self.login()

        provided_evidences_url = reverse('provided-evidences')

        response = self.client.get(provided_evidences_url, {}, format='json')

        expected_provided_evidences = ['authenticated',
                                       'knowledge_factor',
                                       'knowledge_factor_password',
                                       'knowledge_factor_password_confirmation']



        self.assertResponseStatus(response, status.HTTP_200_OK)
        self.assertListEqual(sorted(response.data.get('result').get('provided-evidences')),
                             sorted(expected_provided_evidences))

        expected_provided_evidences = ['authenticated',
                                       'knowledge_factor',
                                       'knowledge_factor_password',
                                       'knowledge_factor_password_confirmation',
                                       'ownership_factor',
                                       'ownership_factor_otp_token',
                                       'ownership_factor_google_authenticator']
        self.add_evidence_google()

        response = self.client.get(provided_evidences_url, {}, format='json')

        response_list = response.data.get('result').get('provided-evidences')
        self.assertListEqual(sorted(response_list), sorted(expected_provided_evidences))


class TestPasswordChangeInsecure(TestUtils):
    url = reverse('password-change-insecure')

    def test_password_change_insecure(self):
        from talos.models import OneTimePasswordCredential
        from talos.models import Principal
        import pyotp

        self.create_user()
        self.login()
        self.add_evidence_sms()

        self.assertEqual(OneTimePasswordCredential.objects.all().count(), 1)
        sms_otp_credential = OneTimePasswordCredential.objects.last()

        totp = pyotp.TOTP(sms_otp_credential.salt.decode())
        sms_code = totp.now()

        data = {
            'password' : self.password,
            'new_password' : '1234567',
            'sms_code' : sms_code
        }

        response = self.client.put(self.url, data, format='json')

        self.assertResponseStatus(response, status.HTTP_200_OK)

        principal = Principal.objects.last()
        self.assertFalse(principal.check_password(self.password))
        self.assertTrue(principal.check_password('1234567'))

    def test_clear_evidences_for_other_users(self):
        from datetime import datetime, timedelta
        from talos.models import OneTimePasswordCredential
        from talos.models import Principal
        from talos.models import Session
        from django.db.models import Q
        import pyotp

        self.create_user()
        self.login()
        self.add_evidence_sms()

        self.assertEqual(OneTimePasswordCredential.objects.all().count(), 1)
        sms_otp_credential = OneTimePasswordCredential.objects.last()

        totp = pyotp.TOTP(sms_otp_credential.salt.decode())
        sms_code = totp.now()

        data = {
            'password' : self.password,
            'new_password' : '1234567',
            'sms_code' : sms_code
        }

        Session.objects.create(principal=self.principal, evidences='evidences')
        Session.objects.create(principal=self.principal, evidences='evidences')

        # Add another Session where valid_till is invalid (less than current time)
        Session.objects.create(principal=self.principal, evidences='evidences',
                               valid_till=datetime.now() - timedelta(hours=24))

        self.assertEqual(4, Session.objects.all().count())

        response = self.client.put(self.url, data, format='json')

        self.assertResponseStatus(response, status.HTTP_200_OK)

        principal = Principal.objects.last()
        self.assertFalse(principal.check_password(self.password))
        self.assertTrue(principal.check_password('1234567'))

        # Two row has been updated correctly (principal, valid_till)
        self.assertEqual(2, Session.objects.filter(principal=self.principal, evidences=None).count())
        self.assertEqual(2, Session.objects.filter(Q(principal=self.principal), ~Q(evidences=None)).count())


class TestPasswordChangeSecure(TestUtils):
    url = reverse('password-change-secure')

    def test_password_change_secure(self):
        from talos.models import OneTimePasswordCredential
        from talos.models import Principal
        import pyotp

        self.create_user()
        self.login()
        self.add_evidence_google()

        self.assertEqual(OneTimePasswordCredential.objects.all().count(), 1)
        google_otp_credential = OneTimePasswordCredential.objects.last()
        secret = google_otp_credential.salt
        totp = pyotp.TOTP(secret)
        google_otp_code = totp.now()

        data = {
            'password' : self.password,
            'new_password' : '1234567',
            'google_otp_code' : google_otp_code
        }


        response = self.client.put(self.url, data, format='json')

        self.assertResponseStatus(response, status.HTTP_200_OK)

        principal = Principal.objects.last()
        self.assertFalse(principal.check_password(self.password))
        self.assertTrue(principal.check_password('1234567'))

class TestAddGoogleAuthenticator(TestUtils):
    request_url = reverse('google-authenticator-activate-request')
    confirm_url = reverse('google-authenticator-activate-confirm')


    def test_add_google_authentictor(self):
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import OneTimePasswordCredential
        import pyotp

        self.create_user()
        self.login()
        self.add_evidence_sms()

        data = {
            'password' : self.password
        }

        response = self.client.post(self.request_url, data, format='json')


        self.assertResponseStatus(response, status.HTTP_200_OK)
        self.assertTrue(response.data.get('result').get('secret', False))
        secret = response.data.get('result').get('secret')

        totp = pyotp.TOTP(secret)
        code = totp.now()

        data = {
            'code' : code
        }

        self.assertFalse(self.principal.profile.is_secure)

        response = self.client.post(self.confirm_url, data, format='json')

        self.assertResponseStatus(response, status.HTTP_201_CREATED)

        google_otp_directory = OneTimePasswordCredentialDirectory.objects.get(code='onetimepassword_internal_google_authenticator')
        otp_credential = OneTimePasswordCredential.objects.last()

        self.assertEqual(otp_credential.directory, google_otp_directory)
        self.assertEqual(otp_credential.principal, self.principal)
        self.assertEqual(otp_credential.salt.decode(), secret)

        principal = Principal.objects.get(pk=self.principal.pk)
        self.assertTrue(principal.profile.is_secure)

class TestGoogleAuthenticatorDelete(TestUtils):
    request_url = reverse('google-authenticator-delete-request')
    confirm_url = reverse('google-authenticator-delete-confirm')

    def test_google_authenticator_delete(self):
        from talos.models import ValidationToken
        from talos.models import OneTimePasswordCredentialDirectory
        from talos.models import OneTimePasswordCredential
        import pyotp

        self.create_user()
        self.login()
        self.add_evidence_sms()

        response = self.client.post(self.request_url, {}, format='json')

        self.assertResponseStatus(response, status.HTTP_403_FORBIDDEN)

        self.add_evidence_google()

        response = self.client.post(self.request_url, {}, format='json')

        self.assertResponseStatus(response, status.HTTP_200_OK)

        validation_token = ValidationToken.objects.last()
        self.assertEqual(validation_token.principal, self.principal)
        self.assertEqual(validation_token.type, 'otp_delete')


        sms_otp_directory = OneTimePasswordCredentialDirectory.objects.get(code='onetimepassword_internal_phone_sms_authenticator')
        google_otp_directory = OneTimePasswordCredentialDirectory.objects.get(code='onetimepassword_internal_google_authenticator')


        sms_otp_credential = OneTimePasswordCredential.objects.get(principal=self.principal,
                                                                   directory=sms_otp_directory)
        google_otp_credential = OneTimePasswordCredential.objects.get(principal=self.principal,
                                                                      directory=google_otp_directory)

        totp = pyotp.TOTP(sms_otp_credential.salt.decode())
        sms_code = totp.now()
        totp = pyotp.TOTP(google_otp_credential.salt)
        google_code = totp.now()

        data = {
            'sms_code' : sms_code,
            'google_otp_code' : google_code,
            'password' : self.password,
            'token' : validation_token.secret
        }

        response = self.client.post(self.confirm_url, data, format='json')

        self.assertResponseStatus(response, status.HTTP_200_OK)
        self.assertEqual(OneTimePasswordCredential.objects.filter(directory=google_otp_directory).count(), 0)



class TestSendSms(TestUtils):
    def test_send_sms(self):
        from talos.contrib.sms_sender import SMSSender
        sms_sender = SMSSender()
        #sms_sender.send_message('+995599439670', 'Message')