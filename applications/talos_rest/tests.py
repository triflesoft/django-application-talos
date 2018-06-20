from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from rest_framework import status

from talos.models import ValidationToken


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

        self.principal = Principal.objects.create(full_name=self.full_name,
                                             phone=self.phone,
                                             email=self.email)

        self.principal.set_password(self.password)
        self.principal.save()

        basic_identity = BasicIdentity()
        basic_identity.principal = self.principal
        basic_identity.email = self.email
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
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def assertResponseStatus(self, response, status = status.HTTP_200_OK):
        self.assertEquals(response.status_code, status)
        self.assertEquals(response.data['status'], status)

class TestRegistration(APITestCase):
    def test_registration(self):
        from talos.models import PhoneSMSValidationToken
        from talos.models import Principal
        from talos.models import BasicIdentity

        phone = '+995599439670'

        phone_validation_token = PhoneSMSValidationToken()
        phone_validation_token.phone = phone
        phone_validation_token.save()

        url = reverse('basic-registration')

        data = {
            'full_name': 'Giorgi Fafakerashvili',
            'email': 'giorgi.fafa@gmail.com',
            'password': '123456',
            'token': phone_validation_token.secret,
            'code': phone_validation_token.salt.decode(),
            'phone': phone,
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

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

        data = {

        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(response.data.get('error', False))


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

        self.assertResponseStatus(response, status.HTTP_200_OK)

        self.assertEqual(response_data['result']['email'], self.email)

    def test_user_login_incorrect_credentials(self):
        self.create_user()


        data = {
            'email': 'test@test.ge',
            'password': 'test'
        }

        response = self.client.post(self.url, data, format='json')
        response_data = response.data

        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)

        self.assertEqual(response_data['error']['email'][0], 'username_invalid')

    def test_user_login_invalid_credentials(self):
        self.create_user()


        data = {}

        response = self.client.post(self.url, data, format='json')
        response_data = response.data

        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)

        self.assertEqual(response_data['error']['email'][0], 'required')
        self.assertEqual(response_data['error']['password'][0], 'required')
        self.assertTrue(response_data.get('details'), False)

    def test_get_session_after_successful_login(self):
        from talos.models import  Session

        self.create_user()
        self.login()

        session = Session.objects.last()

        response = self.client.get(self.url)
        response_data = response.data

        self.assertResponseStatus(response, status.HTTP_200_OK)
        self.assertEqual(session.uuid, response_data['result']['session_id'])

    def test_get_session_when_no_login(self):
        response = self.client.get(self.url)

        self.assertResponseStatus(response, status.HTTP_404_NOT_FOUND)
    def test_logout_when_user_isnot_log_in(self):
        response = self.client.delete(self.url)

        self.assertResponseStatus(response, status.HTTP_404_NOT_FOUND)

    def test_logout_when_user_is_log_in(self):
        self.create_user()
        self.login()

        response = self.client.delete(self.url)

        self.assertResponseStatus(response, status.HTTP_200_OK)


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

class TestEmailChange(TestUtils):
    email_change_request_url  = reverse("email-change-request")



    def test_get_method_on_email_change(self):

        response = self.client.get(self.email_change_request_url)
        self.assertResponseStatus(response, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEquals(response.data.get('error'), 'method_not_allowed')


    def test_email_change_request_when_no_data(self):
        self.create_user()
        self.login()
        # TODO login with sms

        data = {}
        response = self.client.post(self.email_change_request_url,data)
        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('new_email'),['required'])

    def test_email_change_request_when_invalid_email(self):
        self.create_user()
        self.login()
        # TODO login with sms

        data = {'new_email' : 'asd'}
        response = self.client.post(self.email_change_request_url, data)
        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('new_email'), ['email_invalid'])

    def test_email_change_request_when_passed_used_email(self):
        self.create_user()
        self.login()
        # TODO login with sms

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
        # TODO login with sms

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

        response = self.client.get(url)

        self.assertResponseStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertListEqual(response.data.get('error').get('secret'),['token_invalid'])

    def test_email_change_token_validation_when_success(self):
        self.create_user()
        self.login()
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


