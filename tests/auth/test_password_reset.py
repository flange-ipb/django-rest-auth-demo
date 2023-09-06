import re

from django.urls import reverse
from rest_framework import status

from tests.utils import register_and_verify, REGISTER_PAYLOAD, login


def extract_password_reset_email(email):
    m = re.search(
        r"password-reset/confirm/(?P<uid>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,32})",
        email
    )
    return m.group("uid"), m.group("token")


def test_password_reset_via_email(db, api_client, mailoutbox):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
    mailoutbox.clear()
    assert len(mailoutbox) == 0

    payload = {"email": REGISTER_PAYLOAD["email"]}
    response = api_client.post(reverse("rest_password_reset"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'detail': 'Password reset e-mail has been sent.'}
    assert len(mailoutbox) == 1
    email = mailoutbox[0].body

    # username is not part of the email
    assert f'username is {REGISTER_PAYLOAD["username"]}' not in email

    # extract user id and token from the email and send it to the confirm endpoint
    uid, confirm_token = extract_password_reset_email(email)

    new_pw = "test1234"
    payload = {"uid": uid, "token": confirm_token, "new_password1": new_pw, "new_password2": new_pw}
    response = api_client.post(reverse("rest_password_reset_confirm"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {"detail": "Password has been reset with the new password."}

    # can log in with new password
    payload = {"email": REGISTER_PAYLOAD["email"], "password": new_pw}
    response = login(api_client, payload)

    assert response.status_code == status.HTTP_200_OK
    access_token = response.data["access"]
    assert access_token is not None


def test_cannot_reuse_password_reset_confirm_token(db, api_client, mailoutbox):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
    mailoutbox.clear()

    payload = {"email": REGISTER_PAYLOAD["email"]}
    api_client.post(reverse("rest_password_reset"), payload)
    uid, confirm_token = extract_password_reset_email(mailoutbox[0].body)

    # reset password
    new_pw = "test1234"
    payload = {"uid": uid, "token": confirm_token, "new_password1": new_pw, "new_password2": new_pw}
    api_client.post(reverse("rest_password_reset_confirm"), payload)

    # try to reset the password a second time
    new_pw2 = "test9876"
    payload = {"uid": uid, "token": confirm_token, "new_password1": new_pw2, "new_password2": new_pw2}
    response = api_client.post(reverse("rest_password_reset_confirm"), payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"token":["Invalid value"]}'
    # Why is this happening?
    # user.password is part of the token, so the first password reset invalidates it. See
    # https://github.com/django/django/blob/74b5074174d1749ee44df2f7ed418010a7a4ac70/django/contrib/auth/tokens.py#L122


def test_cannot_reset_password_of_other_user_with_token(db, api_client, mailoutbox):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
    mailoutbox.clear()

    payload = {"username": "user2", "password1": "test1234", "password2": "test1234", "email": "user@user.example"}
    register_and_verify(api_client, payload, mailoutbox)
    mailoutbox.clear()

    payload = {"email": REGISTER_PAYLOAD["email"]}
    api_client.post(reverse("rest_password_reset"), payload)
    _, confirm_token = extract_password_reset_email(mailoutbox[0].body)

    # try to reset password
    new_pw = "test1234"
    payload = {"uid": 2, "token": confirm_token, "new_password1": new_pw, "new_password2": new_pw}
    response = api_client.post(reverse("rest_password_reset_confirm"), payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"token":["Invalid value"]}'
    # Why is this happening?
    # user.pk is part of the token. See
    # https://github.com/django/django/blob/74b5074174d1749ee44df2f7ed418010a7a4ac70/django/contrib/auth/tokens.py#L122


# Is this a security issue? Probably not.
def test_can_enumerate_user_ids_with_password_reset_confirm(db, api_client, mailoutbox):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)

    new_pw = "test1234"
    payload = {"uid": 1, "token": "xxx", "new_password1": new_pw, "new_password2": new_pw}
    response = api_client.post(reverse("rest_password_reset_confirm"), payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"token":["Invalid value"]}'

    payload = {"uid": 2, "token": "xxx", "new_password1": new_pw, "new_password2": new_pw}
    response = api_client.post(reverse("rest_password_reset_confirm"), payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"uid":["Invalid value"]}'


def test_password_reset_with_unknown_email_address_does_not_send_email(db, api_client, mailoutbox):
    payload = {"email": REGISTER_PAYLOAD["email"]}

    response = api_client.post(reverse("rest_password_reset"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'detail': 'Password reset e-mail has been sent.'}
    assert len(mailoutbox) == 0


def test_password_reset_confirm_view_does_nothing(db, requests_client):
    url = f'http://testserver{reverse("password_reset_confirm", kwargs={"uid": 1, "token": "some token"})}'

    response = requests_client.delete(url)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = requests_client.get(url)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = requests_client.patch(url)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = requests_client.post(url)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = requests_client.put(url)
    assert response.status_code == status.HTTP_404_NOT_FOUND
