from django.urls import reverse
from rest_framework import status

from tests.utils import register_and_login, REGISTER_PAYLOAD, logout


def test_refresh_successful_get_new_access_token(db, api_client, mailoutbox):
    _, refresh_token = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)

    payload = {"refresh": refresh_token}
    response = api_client.post(reverse("token_refresh"), payload)

    assert response.status_code == status.HTTP_200_OK
    new_access_token = response.data["access"]

    # new token is valid
    response = api_client.post(reverse("token_verify"), {"token": new_access_token})
    assert response.status_code == status.HTTP_200_OK


def test_refresh_with_blacklisted_token(db, api_client, mailoutbox):
    access_token, refresh_token = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
    logout(api_client, refresh_token)

    payload = {"refresh": refresh_token}
    response = api_client.post(reverse("token_refresh"), payload)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.content.decode() == '{"detail":"Token is blacklisted","code":"token_not_valid"}'


def test_refresh_with_invalid_token(db, api_client, mailoutbox):
    _, refresh_token = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)

    # manipulate the signature block
    invalid_token = refresh_token[:-5] + refresh_token[-4:]
    assert refresh_token != invalid_token

    payload = {"refresh": invalid_token}
    response = api_client.post(reverse("token_refresh"), payload)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.content.decode() == '{"detail":"Token is invalid or expired","code":"token_not_valid"}'
