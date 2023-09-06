import re

from django.urls import reverse

REGISTER_PAYLOAD = {"username": "test", "password1": "testtest", "password2": "testtest", "email": "test@test.example"}


def register_user(client, payload):
    response = client.post(reverse("rest_register"), payload)
    return response


def login(client, payload):
    return client.post(reverse("rest_login"), payload)


def register_and_verify(client, register_payload, mailbox):
    register_user(client, register_payload)

    payload = {"key": extract_email_verify_email(mailbox[0].body)}
    client.post(reverse("rest_verify_email"), payload)


def register_and_login(client, register_payload, mailbox):
    register_and_verify(client, register_payload, mailbox)

    payload = {"email": register_payload["email"], "password": register_payload["password1"]}
    login_data = login(client, payload).data
    return login_data["access"], login_data["refresh"]


def logout(client, refresh_token):
    payload = {"refresh": refresh_token}
    return client.post(reverse("rest_logout"), payload)


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def extract_email_verify_email(email):
    return re.search(r"account-confirm-email/(?P<key>[-:\w]+)", email).group("key")
