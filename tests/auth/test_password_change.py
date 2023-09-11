from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status

from tests.utils import register_and_login, REGISTER_PAYLOAD, auth_header


def test_password_change_successful(db, api_client, mailoutbox):
    access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
    headers = auth_header(access_token)
    new_pw = "test1234"
    old_pw_in_db = get_user_model().objects.get(pk=1).password

    payload = {"new_password1": new_pw, "new_password2": new_pw, "old_password": REGISTER_PAYLOAD["password1"]}
    response = api_client.post(reverse("rest_password_change"), payload, headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'detail': 'New password has been saved.'}

    # password was changed in the database
    assert get_user_model().objects.get(pk=1).password != old_pw_in_db


def test_password_change_fails_due_to_wrong_old_password(db, api_client, mailoutbox):
    access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
    headers = auth_header(access_token)
    new_pw = "test1234"
    old_pw_in_db = get_user_model().objects.get(pk=1).password

    payload = {"new_password1": new_pw, "new_password2": new_pw, "old_password": "wrong password"}
    response = api_client.post(reverse("rest_password_change"), payload, headers=headers)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"old_password":' \
                                        '["Your old password was entered incorrectly. Please enter it again."]}'

    # password wasn't changed in the database
    assert get_user_model().objects.get(pk=1).password == old_pw_in_db


def test_password_change_fails_due_to_new_password_mismatch(db, api_client, mailoutbox):
    access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
    headers = auth_header(access_token)
    old_pw_in_db = get_user_model().objects.get(pk=1).password

    payload = {"new_password1": "test1234", "new_password2": "1234test",
               "old_password": REGISTER_PAYLOAD["password1"]}
    response = api_client.post(reverse("rest_password_change"), payload, headers=headers)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"new_password2":["The two password fields didn’t match."]}'

    # password wasn't changed in the database
    assert get_user_model().objects.get(pk=1).password == old_pw_in_db
