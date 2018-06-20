from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from rest_framework import status


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
        from talos.models import  Session

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

