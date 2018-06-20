from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from rest_framework import status

from talos.models import ValidationToken

from utils import SuccessResponse, ErrorResponse

HTTP_HOST = 'localhost:8000'


class TalosRestTest(APITestCase):
    # Principal Registration
    # /principal/registration_request
    registration_url = '/api/principal/registration_token/{secret}'
    registration_data = {
        "brief_name": 'Alexandre',
        "full_name": 'Begijanovi',
        "username": 'asakura',
        "password1": '123qwe123qwe',
        "password2": '123qwe123qwe',
    }

    def test_principal_registration_request(self):
        url = reverse('talos-rest-principal-regisration-request')

        data = {'email': 'test@bixtrim.com'}

        response = self.client.post(url, data, format='json', HTTP_HOST=HTTP_HOST)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        token = ValidationToken.objects.first()

        self.assertDictEqual(data, response.data['result'])
        self.assertEqual(ValidationToken.objects.count(), 1)
        self.assertEqual(data['email'], token.email)

    def test_principal_registration_request_two_times(self):
        url = reverse('talos-rest-principal-regisration-request')

        data = {'email': 'test@bixtrim.com'}

        response = self.client.post(url, data, format='json', HTTP_HOST=HTTP_HOST)
        response = self.client.post(url, data, format='json', HTTP_HOST=HTTP_HOST)

        self.assertDictEqual(data, response.data['result'])
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(ValidationToken.objects.count(), 2)

    def test_principal_registration_request_incorrect_mail_format(self):
        url = reverse('talos-rest-principal-regisration-request')

        data = {'email': 'test'}

        response = self.client.post(url, data, format='json', HTTP_HOST=HTTP_HOST)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        compare_data = ErrorResponse()
        compare_data.set_error_pairs('email', 'invalid_email')
        compare_data.set_details_pairs('email', 'E-mail address is ill-formed')
        compare_data.set_docs(response.data['docs'])
        self.assertDictEqual(compare_data.response, response.data)

    # Registration token validation.
    # /api/registration_token/{secret}

    def test_registration_token_validation_when_invalid_token(self):
        failed_secret = '123'
        url = '/api/registration_token/{secret}'.format(secret=failed_secret)
        response = self.client.get(url, HTTP_HOST=HTTP_HOST)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_registration_token_validation_passed(self):
        url = reverse('talos-rest-principal-regisration-request')
        data = {'email': 'test@bixtrim.com'}
        response = self.client.post(url, data, format='json', HTTP_HOST=HTTP_HOST)
        token = ValidationToken.objects.first().secret

        url = '/api/registration_token/{secret}'.format(secret=token)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        compare_data = SuccessResponse()
        compare_data.set_result_pairs('secret', token)
        self.assertDictEqual(compare_data.response, response.data)

    def test_principal_registration_invalid_token(self):
        secret = '123'

        response = self.client.post(self.registration_url.format(secret=secret),
                                    self.registration_data, format='json', HTTP_HOST=HTTP_HOST)
        compare_data = ErrorResponse()
        compare_data.set_error_pairs('non_field_errors', 'invalid_token')
        compare_data.set_details_pairs('non_field_errors', 'Token is not valid.')
        compare_data.set_docs(response.data['docs'])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(compare_data.response, response.data)

    # Registration  /api/principal/registration_token/{secret}

    def test_principal_registration_invalid_password(self):
        registration_data = dict(self.registration_data)

        registration_data['password1'] = '1234'
        registration_data['password2'] = '1234'
        # Create registration token
        url = reverse('talos-rest-principal-regisration-request')
        data = {'email': 'test@bixtrim.com'}
        token_response = self.client.post(url, data, format='json', HTTP_HOST=HTTP_HOST)
        token = ValidationToken.objects.first()
        response = self.client.post(self.registration_url.format(secret=token),
                                    registration_data, format='json', HTTP_HOST=HTTP_HOST)
        compare_data = ErrorResponse()
        compare_data.set_error_pairs('password', ['invalid', 'invalid', 'invalid'])
        compare_data.set_details_pairs('password', [
            'This password is too short. It must contain at least 8 characters.',
            'This password is too common.', 'This password is entirely numeric.'])
        compare_data.set_docs(response.data['docs'])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(compare_data.response, response.data)

    def test_principal_registration_when_principal_already_exists(self):
        # Create registration token
        url = reverse('talos-rest-principal-regisration-request')
        data = {'email': 'test@bixtrim.com'}
        token_response = self.client.post(url, data, format='json', HTTP_HOST=HTTP_HOST)
        token = ValidationToken.objects.first()
        response = self.client.post(self.registration_url.format(secret=token),
                                    self.registration_data, format='json', HTTP_HOST=HTTP_HOST)
        response = self.client.post(self.registration_url.format(secret=token),
                                    self.registration_data, format='json', HTTP_HOST=HTTP_HOST)

        compare_data = ErrorResponse()
        compare_data.set_error_pairs('username', 'invalid_username')
        compare_data.set_details_pairs('username', 'Username is already taken')
        compare_data.set_docs(response.data['docs'])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(compare_data.response, response.data)

    def test_principal_registration_when_password_didnt_match(self):
        # Create registration token
        registration_data = dict(self.registration_data)
        registration_data['password1'] = '123123123'
        url = reverse('talos-rest-principal-regisration-request')
        data = {'email': 'test@bixtrim.com'}
        token_response = self.client.post(url, data, format='json', HTTP_HOST=HTTP_HOST)
        token = ValidationToken.objects.first()
        response = self.client.post(self.registration_url.format(secret=token),
                                    registration_data, format='json', HTTP_HOST=HTTP_HOST)

        compare_data = ErrorResponse()
        compare_data.set_error_pairs('password2', 'invalid_password_confirmation')
        compare_data.set_details_pairs('password2', 'Passwords do not match.')
        compare_data.set_docs(response.data['docs'])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(compare_data.response, response.data)

    # Email change /api/principal/email/request
    def test_principal_email_change_invalid_email(self):
        url = reverse('talos-email-change-request')
        data = {'email' : 'test'}