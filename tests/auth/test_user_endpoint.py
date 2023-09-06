from django.urls import reverse
from rest_framework import status

from tests.utils import register_and_login, REGISTER_PAYLOAD, auth_header


def test_change_user_info(db, api_client, mailoutbox):
    access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
    headers = auth_header(access_token)

    payload = {"username": "user123", "first_name": "firstname", "last_name": "lastname"}
    response = api_client.put(reverse("rest_user_details"), payload, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'pk': 1, 'username': 'user123', 'email': 'test@test.example',
                             'first_name': 'firstname', 'last_name': 'lastname'}


def test_user_cannot_change_email(db, api_client, mailoutbox):
    access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
    headers = auth_header(access_token)
    user_before = api_client.get(reverse("rest_user_details"), headers=headers).data

    payload = {"email": "abc@def.example"}
    response = api_client.patch(reverse("rest_user_details"), payload, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    user_after = api_client.get(reverse("rest_user_details"), headers=headers).data
    assert user_after == user_before


def test_cannot_delete_user(db, api_client, mailoutbox):
    access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
    headers = auth_header(access_token)

    response = api_client.delete(reverse("rest_user_details"), headers=headers)

    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
