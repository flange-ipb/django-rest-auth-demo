from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from tests.utils import register_and_verify, REGISTER_PAYLOAD, login, user_obj


def test_can_login_with_email(db, api_client, mailoutbox):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
    assert user_obj(REGISTER_PAYLOAD["email"]).last_login is None

    payload = {"email": REGISTER_PAYLOAD["email"], "password": REGISTER_PAYLOAD["password1"]}
    response = login(api_client, payload)

    assert response.status_code == status.HTTP_200_OK

    # User's last_login field is NOT updated!
    # see https://github.com/iMerica/dj-rest-auth/issues/531
    assert user_obj(REGISTER_PAYLOAD["email"]).last_login is None

    # validate access token
    access_token = response.data["access"]
    assert access_token is not None
    at_obj = AccessToken(access_token)
    at_obj.verify()
    at_obj.verify_token_type()
    assert at_obj.get("user_id") == user_obj(REGISTER_PAYLOAD["email"]).id

    # validate refresh token
    refresh_token = response.data["refresh"]
    assert refresh_token is not None
    rt_obj = RefreshToken(refresh_token)
    rt_obj.verify()
    rt_obj.verify_token_type()
    assert rt_obj.get("user_id") == user_obj(REGISTER_PAYLOAD["email"]).id

    assert response.data["user"] == {'pk': user_obj(REGISTER_PAYLOAD["email"]).id,
                                     'username': user_obj(REGISTER_PAYLOAD["email"]).username,
                                     'email': REGISTER_PAYLOAD["email"],
                                     'first_name': '',
                                     'last_name': ''}


def test_cannot_login_with_username(db, api_client, mailoutbox):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)

    payload = {"username": "", "password": REGISTER_PAYLOAD["password1"]}
    response = login(api_client, payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"non_field_errors":["Must include \\"email\\" and \\"password\\"."]}'


def test_cannot_login_with_wrong_password(db, api_client, mailoutbox):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)

    payload = {"email": REGISTER_PAYLOAD["email"], "password": "wrong password"}
    response = login(api_client, payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"non_field_errors":["Unable to log in with provided credentials."]}'


def test_inactive_user_cannot_login(db, api_client, mailoutbox):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)

    user = user_obj(REGISTER_PAYLOAD["email"])
    user.is_active = False
    user.save()

    payload = {"email": REGISTER_PAYLOAD["email"], "password": REGISTER_PAYLOAD["password1"]}
    response = login(api_client, payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"non_field_errors":["Unable to log in with provided credentials."]}'
