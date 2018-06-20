from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from rest_framework import status

from talos.models import ValidationToken

from .utils import SuccessResponse, ErrorResponse

HTTP_HOST = 'localhost:8000'


class TestUtils(APITestCase):
    def __init__(self, *args, **kwargs):
        self.set_values()
        super(TestUtils, self).__init__(*args, **kwargs)

    def set_values(self,
                   full_name='bixtrim',
                   email='at@bixtrim.com',
                   password='bixtrim_password',
                   phone='+995555555555'):
        self.full_name = full_name
        self.email = email
        self.password = password
        self.phone = phone

    def create_user(self):
        from talos.models import Principal
        from talos.models import BasicIdentity
        from talos.models import BasicIdentityDirectory

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


class TestRegistration(APITestCase):
    def test_registration(self):
        from talos.models import PhoneSMSValidationToken
        from talos_rest.utils import ErrorResponse
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


class TestLogin(TestUtils):
    def test_user_login(self):
        self.create_user()

        url = reverse('talos-rest-sessions')

        data = {
            'email' : self.email,
            'password' : self.password
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
