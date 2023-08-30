import re

from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.authtoken.models import Token

REGISTER_PAYLOAD = {"username": "test", "password1": "testtest", "password2": "testtest", "email": "test@test.example"}


def test_registration_successful_get_token_immediately_and_no_email_sent(db, api_client, mailoutbox):
    assert len(User.objects.all()) == 0
    assert len(Token.objects.all()) == 0

    response = register_user(api_client, REGISTER_PAYLOAD)

    assert response.status_code == status.HTTP_201_CREATED

    # we get a token
    token = response.data["key"]
    assert token is not None

    # user object was created
    assert len(User.objects.all()) == 1
    user = User.objects.get(pk=1)
    assert user.username == REGISTER_PAYLOAD["username"]
    assert user.email == REGISTER_PAYLOAD["email"]

    # token is in the database
    assert len(Token.objects.all()) == 1
    assert Token.objects.all()[0].key == token

    # no email was sent
    assert len(mailoutbox) == 0


def test_registration_fails_due_to_password_missmatch(db, api_client):
    payload = {"username": "test", "password1": "test1234", "password2": "testtest", "email": "test@test.example"}

    response = api_client.post(reverse("rest_register"), payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"non_field_errors":["The two password fields didn\'t match."]}'


def test_registration_fails_due_to_duplicate_username_and_email(db, api_client):
    register_user(api_client, REGISTER_PAYLOAD)

    response = register_user(api_client, REGISTER_PAYLOAD)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"username":["A user with that username already exists."],' \
                                        '"email":["A user is already registered with this e-mail address."]}'


def test_registration_fails_due_to_missing_fields(db, api_client):
    response = register_user(api_client, {})

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"username":["This field is required."],' \
                                        '"email":["This field is required."],' \
                                        '"password1":["This field is required."],' \
                                        '"password2":["This field is required."]}'


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


def test_user_can_login_with_email(db, api_client):
    register_user(api_client, REGISTER_PAYLOAD)

    payload = {"email": REGISTER_PAYLOAD["email"], "password": REGISTER_PAYLOAD["password1"]}
    response = login(api_client, payload)

    assert response.status_code == status.HTTP_200_OK

    # we get a token
    token = response.data["key"]
    assert token is not None


def test_user_cannot_login_with_username(db, api_client):
    register_user(api_client, REGISTER_PAYLOAD)

    payload = {"username": REGISTER_PAYLOAD["username"], "password": REGISTER_PAYLOAD["password1"]}
    response = login(api_client, payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"non_field_errors":["Must include \\"email\\" and \\"password\\"."]}'


def test_password_reset_via_email(db, api_client, mailoutbox):
    assert len(mailoutbox) == 0
    register_user(api_client, REGISTER_PAYLOAD)

    payload = {"email": REGISTER_PAYLOAD["email"]}
    response = api_client.post(reverse("rest_password_reset"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert len(mailoutbox) == 1
    email = mailoutbox[0].body

    # username is not part of the email
    assert f'username is {REGISTER_PAYLOAD["username"]}' not in email

    # extract user id and token from the email and send it to the confirm endpoint
    m = re.search(
        r"password-reset/confirm/(?P<uid>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,32})",
        email
    )

    new_pw = "test1234"
    payload = {"uid": m.group("uid"), "token": m.group("token"), "new_password1": new_pw, "new_password2": new_pw}
    response = api_client.post(reverse("rest_password_reset_confirm"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {"detail": "Password has been reset with the new password."}

    # can log in with new password
    payload = {"email": REGISTER_PAYLOAD["email"], "password": new_pw}
    response = login(api_client, payload)

    assert response.status_code == status.HTTP_200_OK
    token = response.data["key"]
    assert token is not None


def test_password_change_successful(db, api_client):
    token = register_user(api_client, REGISTER_PAYLOAD).data["key"]
    headers = auth_header(token)
    new_pw = "test1234"
    old_pw_in_db = User.objects.get(pk=1).password

    payload = {"new_password1": new_pw, "new_password2": new_pw, "old_password": REGISTER_PAYLOAD["password1"]}
    response = api_client.post(reverse("rest_password_change"), payload, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'detail': 'New password has been saved.'}

    # password was changed in the database
    assert User.objects.get(pk=1).password != old_pw_in_db

    # token is still active
    assert Token.objects.all()[0].key == token


def test_password_change_fails_due_to_wrong_old_password(db, api_client):
    token = register_user(api_client, REGISTER_PAYLOAD).data["key"]
    headers = auth_header(token)
    new_pw = "test1234"
    old_pw_in_db = User.objects.get(pk=1).password

    payload = {"new_password1": new_pw, "new_password2": new_pw, "old_password": "wrong password"}
    response = api_client.post(reverse("rest_password_change"), payload, headers=headers)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"old_password":' \
                                        '["Your old password was entered incorrectly. Please enter it again."]}'

    # password wasn't changed in the database
    assert User.objects.get(pk=1).password == old_pw_in_db


def test_password_change_fails_due_to_new_password_mismatch(db, api_client):
    token = register_user(api_client, REGISTER_PAYLOAD).data["key"]
    headers = auth_header(token)
    old_pw_in_db = User.objects.get(pk=1).password

    payload = {"new_password1": "test1234", "new_password2": "1234test", "old_password": REGISTER_PAYLOAD["password1"]}
    response = api_client.post(reverse("rest_password_change"), payload, headers=headers)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"new_password2":["The two password fields didn’t match."]}'

    # password wasn't changed in the database
    assert User.objects.get(pk=1).password == old_pw_in_db


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
