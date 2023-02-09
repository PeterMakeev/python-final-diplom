import pytest
from django.urls import reverse
from backend.models import User, Contact
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token


class APITests(APITestCase):
    def test_register_account(self):
        """
        Проверка регистрации пользователя
        """
        count = User.objects.count()
        data_user = {
            'first_name': 'Testfirstname',
            'last_name': 'Testlastname',
            'email': 'test@test.com',
            'username': 'Testusername',
            'password': 'Testpassword12345',
            'company': 'Testcompany',
            'position': 'Testposition',
            'type': 'buyer',
        }

        url = reverse('backend:user-register')
        response = self.client.post(url, data_user)

        assert response.status_code == 200
        assert response.data['status'] is True
        assert User.objects.count() == count + 1

    def test_create_contact(self):
        """
        Проверка создания контактов пользователя
        """
        data_user = {
            'first_name': 'Testfirstname',
            'last_name': 'Testlastname',
            'email': 'test@test.com',
            'username': 'Testusername',
            'password': 'Testpassword12345',
            'company': 'Testcompany',
            'position': 'Testposition',
            'type': 'buyer',
            'is_active': True
        }
        count = Contact.objects.count()
        user = User.objects.create_user(**data_user)
        url = reverse('backend:user-contact')
        token = Token.objects.create(user=user).key
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        contact = {
            "city": "Testcity",
            "street": "Teststreet",
            "house": "Testhouse",
            "phone":"Testphone"
        }
        response = self.client.post(url, contact)

        assert response.status_code == 201
        assert response.data['status'] is True
        assert Contact.objects.count() == count + 1

    def test_get_account_details(self):
        """
        Проверка получения контактов пользователя
        """
        data_user = {
            'first_name': 'Testfirstname',
            'last_name': 'Testlastname',
            'email': 'test@test.com',
            'username': 'Testusername',
            'password': 'Testpassword12345',
            'company': 'Testcompany',
            'position': 'Testposition',
            'type': 'buyer',
            'is_active': True
        }
        user = User.objects.create_user(**data_user)
        url = reverse('backend:user-details')
        token = Token.objects.create(user=user).key
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        response = self.client.get(url)

        assert response.status_code == 200
