import re

from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.authtoken.models import Token

REGISTER_PAYLOAD = {"username": "test", "password1": "testtest", "password2": "testtest", "email": "test@test.example"}


def test_registration_successful_get_token(db, api_client):
    assert len(User.objects.all()) == 0
    assert len(Token.objects.all()) == 0

    response = register_user(api_client, REGISTER_PAYLOAD)

    assert response.status_code == status.HTTP_201_CREATED
    token = response.data["key"]
    assert token is not None

    assert len(User.objects.all()) == 1
    user = User.objects.get(pk=1)
    assert user.username == REGISTER_PAYLOAD["username"]
    assert user.email == REGISTER_PAYLOAD["email"]

    assert len(Token.objects.all()) == 1
    assert Token.objects.all()[0].key == token


def test_logout_token_is_removed_from_database(db, api_client):
    token = register_user(api_client, REGISTER_PAYLOAD).data["key"]
    assert len(Token.objects.all()) == 1

    response = logout(api_client, token)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {"detail": "Successfully logged out."}
    assert len(Token.objects.all()) == 0


def test_user_cannot_change_email_via_user_endpoint(db, api_client):
    token = register_user(api_client, REGISTER_PAYLOAD).data["key"]
    headers = auth_header(token)
    user_before = api_client.get(reverse("rest_user_details"), headers=headers).data

    payload = {"email": "abc@def.example"}
    response = api_client.patch(reverse("rest_user_details"), payload, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    user_after = api_client.get(reverse("rest_user_details"), headers=headers).data
    assert user_after == user_before


def test_user_cannot_login_with_email(db, api_client):
    token = register_user(api_client, REGISTER_PAYLOAD).data["key"]
    logout(api_client, token)

    payload = {"email": REGISTER_PAYLOAD["email"], "password": REGISTER_PAYLOAD["password1"]}
    response = login(api_client, payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_user_can_login_with_username(db, api_client):
    token = register_user(api_client, REGISTER_PAYLOAD).data["key"]
    logout(api_client, token)

    payload = {"username": REGISTER_PAYLOAD["username"], "password": REGISTER_PAYLOAD["password1"]}
    response = login(api_client, payload)

    assert response.status_code == status.HTTP_200_OK
    token = response.data["key"]
    assert token is not None


def test_password_reset_via_email(db, api_client, mailoutbox):
    assert len(mailoutbox) == 0
    token = register_user(api_client, REGISTER_PAYLOAD).data["key"]
    logout(api_client, token)

    payload = {"email": REGISTER_PAYLOAD["email"]}
    response = api_client.post(reverse("rest_password_reset"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert len(mailoutbox) == 1

    # extract user id and token from the email and send it to the confirm endpoint
    m = re.search(
        r"password-reset/confirm/(?P<uid>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,32})",
        mailoutbox[0].body
    )

    new_pw = "test1234"
    payload = {"uid": m.group("uid"), "token": m.group("token"), "new_password1": new_pw, "new_password2": new_pw}
    response = api_client.post(reverse("rest_password_reset_confirm"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.content == b'{"detail":"Password has been reset with the new password."}'

    # can log in with new password
    payload = {"username": REGISTER_PAYLOAD["username"], "password": new_pw}
    response = login(api_client, payload)

    assert response.status_code == status.HTTP_200_OK
    token = response.data["key"]
    assert token is not None


def register_user(client, payload):
    response = client.post(reverse("rest_register"), payload)
    return response


def login(client, payload):
    return client.post(reverse("rest_login"), payload)


def logout(client, token):
    headers = auth_header(token)
    return client.post(reverse("rest_logout"), headers=headers)


def auth_header(token):
    return {"Authorization": f"Token {token}"}
