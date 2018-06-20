from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from talos_rest import constants


class TestUtils(APITestCase):
    full_name = 'bixtrim'
    email = 'at@bixtrim.com'
    password = 'bixtrim_password'
    phone = '+995555555555'

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

    def create_user(self):
        from talos.models import Principal
        from talos.models import BasicIdentity
        from talos.models import BasicIdentityDirectory
        from talos.models import PrincipalProfile

        principal = Principal.objects.create(full_name=self.full_name,
                                             phone=self.phone,
                                             email=self.email)

        principal.set_password(self.password)
        principal.save()

        basic_identity = BasicIdentity()
        basic_identity.principal = principal
        basic_identity.email = self.email
        basic_identity.directory = BasicIdentityDirectory.objects.get(code='basic_internal')
        basic_identity.save()

        principal_profile  = PrincipalProfile()
        principal_profile.principal = principal
        principal_profile.is_secure = False
        principal_profile.save()

    def login(self):
        data = {
            'email': self.email,
            'password': self.password
        }
        url = reverse('talos-rest-sessions')

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


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
        self.assertEqual(basic_identity.email, principal.email)

    def test_registration_without_phone_sms_token(self):
        data = {
            'full_name': 'Giorgi Fafakerashvili',
            'email': 'giorgi.fafa@gmail.com',
            'password': '123456',
            'token': 'incorrect_token',
            'code': '12345',
            'phone': '12345',
        }

        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(response.data.get('error', False))
        self.assertTrue(response.data.get('error').get('phone', False))
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
            'phone': '+995555555551',
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
            'phone': '+995555555551'
        }

        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], status.HTTP_400_BAD_REQUEST)

        self.assertTrue(response.data.get('error', False))
        self.assertEqual(response.data.get('error').get('token', '')[0], constants.TOKEN_INVALID_CODE)


class TestSessions(TestUtils):
    url = reverse('talos-rest-sessions')

    def test_user_login(self):
        self.create_user()

        data = {
            'email': self.email,
            'password': self.password
        }

        response = self.client.post(self.url, data, format='json')
        response_data = response.data

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response_data['status'], status.HTTP_200_OK)
        self.assertEqual(response_data['result']['email'], self.email)

    def test_user_login_incorrect_credentials(self):
        self.create_user()

        data = {
            'email': 'test@test.ge',
            'password': 'test'
        }

        response = self.client.post(self.url, data, format='json')
        response_data = response.data

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response_data['status'], status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response_data['error']['email'][0], 'username_invalid')

    def test_user_login_invalid_credentials(self):
        self.create_user()

        data = {}

        response = self.client.post(self.url, data, format='json')
        response_data = response.data

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response_data['status'], status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response_data['error']['email'][0], 'required')
        self.assertEqual(response_data['error']['password'][0], 'required')
        self.assertTrue(response_data.get('details'), False)

    def test_get_session_after_successful_login(self):
        from talos.models import Session

        self.create_user()
        self.login()

        session = Session.objects.last()

        response = self.client.get(self.url)
        response_data = response.data

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response_data['status'], status.HTTP_200_OK)
        self.assertEqual(session.uuid, response_data['result']['session_id'])

    def test_get_session_when_no_login(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['status'], status.HTTP_404_NOT_FOUND)

    def test_logout_when_user_isnot_log_in(self):
        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['status'], status.HTTP_404_NOT_FOUND)

    def test_logout_when_user_is_log_in(self):
        self.create_user()
        self.login()

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], status.HTTP_200_OK)


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

        self.assertListEqual(expected_provided_evidences, response.data.get('result').get('provided-evidences', []))



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
            'phone' : '+511123123'
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
            'phone' : '+8855555555',
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
    url  = reverse("email-change-request")

    def test_get_method_on_email_change(self):

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(response.data['status'], status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEquals(response.data.get('error'), 'method_not_allowed')

    def test_email_change_when_not_session(self):

        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['status'], status.HTTP_403_FORBIDDEN)
        self.assertListEqual(response.data.get('error'),
                             ['permission_denied', 'permission_denied', 'permission_denied', 'permission_denied', 'permission_denied'])
        self.assertListEqual(response.data.get('details'),
                             ['authenticated', 'knowledge_factor', 'knowledge_factor_password', 'ownership_factor', 'ownership_factor_otp_token'])

    def test_email_change_when_not_enought_permissions(self):
        self.create_user()
        self.login()
        response = self.client.post(self.url)
        print (response.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['status'], status.HTTP_403_FORBIDDEN)
        # self.assertListEqual(response.data.get('error'),['permission_denied', 'permission_denied'])
        # self.assertListEqual(response.data.get('details'),


