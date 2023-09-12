import uuid

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status

from tests.utils import register_user, REGISTER_PAYLOAD, extract_email_verify_email, user_obj


def test_registration_workflow(db, api_client, mailoutbox):
    assert len(get_user_model().objects.all()) == 1

    response = register_user(api_client, REGISTER_PAYLOAD)

    assert response.status_code == status.HTTP_201_CREATED
    assert response.data == {'detail': 'Verification e-mail sent.'}

    # user object was created
    assert len(get_user_model().objects.all()) == 2
    user = user_obj(REGISTER_PAYLOAD["email"])
    assert user.username
    assert uuid.UUID(user.username)
    assert user.email == REGISTER_PAYLOAD["email"]

    # user has an unverified email address
    email_objs = user.emailaddress_set.all()
    assert len(email_objs) == 1
    assert not email_objs[0].verified

    # verification email was sent
    assert len(mailoutbox) == 1

    # extract verify key from email and send it to the email verification endpoint
    payload = {"key": extract_email_verify_email(mailoutbox[0].body)}

    response = api_client.post(reverse("rest_verify_email"), payload)

    assert response.status_code == status.HTTP_200_OK
    assert response.data == {'detail': 'ok'}

    # user has a verified email address
    email_objs = user.emailaddress_set.all()
    assert len(email_objs) == 1
    assert email_objs[0].verified

    # no new email was sent
    assert len(mailoutbox) == 1


def test_registration_fails_due_to_password_missmatch(db, api_client):
    payload = {"password1": "test1234", "password2": "testtest", "email": "test@test.example"}

    response = api_client.post(reverse("rest_register"), payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"non_field_errors":["The two password fields didn\'t match."]}'


def test_registration_fails_due_to_duplicate_email(db, api_client, mailoutbox):
    register_user(api_client, REGISTER_PAYLOAD)
    mailoutbox.clear()

    response = register_user(api_client, REGISTER_PAYLOAD)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"email":["A user is already registered with this e-mail address."]}'
    assert len(mailoutbox) == 0


def test_registration_fails_due_to_missing_fields(db, api_client):
    response = register_user(api_client, {})

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"email":["This field is required."],' \
                                        '"password1":["This field is required."],' \
                                        '"password2":["This field is required."]}'
