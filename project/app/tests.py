from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.authtoken.models import Token

REGISTER_PAYLOAD = {"username": "test", "password1": "testtest", "password2": "testtest", "email": "test@test.example"}


class UserRegistrationTestCase(TestCase):
    def test_registration_successful(self):
        assert len(User.objects.all()) == 0
        assert len(Token.objects.all()) == 0

        response = self.register_user(REGISTER_PAYLOAD)

        assert response.status_code == status.HTTP_201_CREATED
        token = response.data["key"]
        assert token is not None

        assert len(User.objects.all()) == 1
        user = User.objects.get(pk=1)
        assert user.username == "test"
        assert user.email == "test@test.example"

        assert len(Token.objects.all()) == 1
        assert Token.objects.all()[0].key == token

    def test_logout_successful(self):
        response = self.register_user(REGISTER_PAYLOAD)
        token = response.data["key"]
        assert len(Token.objects.all()) == 1

        headers = {"Authorization": f"Token {token}"}
        response = self.client.post(reverse("rest_logout"), headers=headers)

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {"detail": "Successfully logged out."}
        assert len(Token.objects.all()) == 0

    def register_user(self, payload):
        response = self.client.post(reverse("rest_register"), payload)
        return response
