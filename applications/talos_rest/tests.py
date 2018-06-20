from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from talos.models import ValidationToken

class TalosRestTest(APITestCase):
    def test_principal_registration_request(self):
        url = reverse('talos-rest-principal-regisration-request')

        data = {'email': 'test@bixtrim.com'}

        response = self.client.post(url, data, format='json', HTTP_HOST='example.com')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        token = ValidationToken.objects.first()
        print (token)
        self.assertEqual(ValidationToken.objects.count(), 1)
        self.assertEqual(data['email'],token.email)

    def test_principal_registration_request_two_times(self):
        url = reverse('talos-rest-principal-regisration-request')

        data = {'email': 'test@bixtrim.com'}

        response = self.client.post(url, data, format='json', HTTP_HOST='example.com')
        response = self.client.post(url, data, format='json', HTTP_HOST='example.com')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(ValidationToken.objects.count(), 2)

    def test_registration_token_validation(self):
        url = reverse('talos-rest-principal-regisration-request')

        data = {'email': 'test@bixtrim.com'}

        response = self.client.post(url, data, format='json', HTTP_HOST='example.com')

