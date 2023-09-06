import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

from tests.utils import register_and_login, REGISTER_PAYLOAD, logout, auth_header


def test_logout_refresh_token_gets_blacklisted(db, api_client, mailoutbox):
    access_token, refresh_token = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
    rt_obj = RefreshToken(refresh_token)
    rt_obj.check_blacklist()

    response = logout(api_client, refresh_token)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {"detail": "Successfully logged out."}

    with pytest.raises(TokenError):
        rt_obj = RefreshToken(refresh_token)
        rt_obj.check_blacklist()


def test_after_logout_access_token_is_still_valid(db, api_client, mailoutbox):
    access_token, refresh_token = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
    logout(api_client, refresh_token)

    AccessToken(access_token).verify()  # no exception raised

    # verify access token
    payload = {"token": access_token}
    response = api_client.post(reverse("token_verify"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {}

    # can use access token for authentication
    headers = auth_header(access_token)
    response = api_client.get(reverse("rest_user_details"), headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'pk': 1,
                             'username': REGISTER_PAYLOAD["username"],
                             'email': REGISTER_PAYLOAD["email"],
                             'first_name': '',
                             'last_name': ''}
