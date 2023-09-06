from django.urls import reverse
from rest_framework import status

from tests.utils import register_user, REGISTER_PAYLOAD, extract_email_verify_email, register_and_verify


def test_resend_email_verification_workflow(db, api_client, mailoutbox):
    register_user(api_client, REGISTER_PAYLOAD)
    mailoutbox.clear()

    payload = {"email": REGISTER_PAYLOAD["email"]}
    response = api_client.post(reverse("rest_resend_email"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'detail': 'ok'}
    assert len(mailoutbox) == 1

    payload = {"key": extract_email_verify_email(mailoutbox[0].body)}
    response = api_client.post(reverse("rest_verify_email"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'detail': 'ok'}


# cannot enumerate email addresses
def test_no_resend_because_email_is_already_verified(db, api_client, mailoutbox):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
    mailoutbox.clear()

    payload = {"email": REGISTER_PAYLOAD["email"]}
    response = api_client.post(reverse("rest_resend_email"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'detail': 'ok'}
    assert len(mailoutbox) == 0


# cannot enumerate email addresses
def test_no_resend_due_to_unknown_email(db, api_client, mailoutbox):
    payload = {"email": REGISTER_PAYLOAD["email"]}
    response = api_client.post(reverse("rest_resend_email"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'detail': 'ok'}
    assert len(mailoutbox) == 0


def test_resend_fails_due_to_missing_field(db, api_client, mailoutbox):
    response = api_client.post(reverse("rest_resend_email"), payload={})

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"email":["This field is required."]}'
