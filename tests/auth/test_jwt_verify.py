from django.urls import reverse
from rest_framework import status

from tests.utils import register_and_login, REGISTER_PAYLOAD, logout


def test_verify_valid_tokens(db, api_client, mailoutbox):
    tokens = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)

    for token in tokens:
        payload = {"token": token}
        response = api_client.post(reverse("token_verify"), payload)

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {}


def test_verify_blacklisted_token(db, api_client, mailoutbox):
    access_token, refresh_token = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
    logout(api_client, refresh_token)

    payload = {"token": refresh_token}
    response = api_client.post(reverse("token_verify"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {}


def test_verify_invalid_token(db, api_client, mailoutbox):
    access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)

    # manipulate the signature block
    invalid_token = access_token[:-5] + access_token[-4:]
    assert access_token != invalid_token

    payload = {"token": invalid_token}
    response = api_client.post(reverse("token_verify"), payload)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.content.decode() == '{"detail":"Token is invalid or expired","code":"token_not_valid"}'
