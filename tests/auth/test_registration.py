import uuid

from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status

from tests.utils import register_user, REGISTER_PAYLOAD, extract_verify_email, user_obj, register_and_verify, login


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

    email = mailoutbox[0].body
    assert f"user {user.username} has" in email

    # extract verify key from email and send it to the email verification endpoint
    payload = {"key": extract_verify_email(email)}

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


# Can be used for enumeration!
def test_registration_fails_due_to_duplicate_email(db, api_client, mailoutbox):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
    mailoutbox.clear()

    response = register_user(api_client, REGISTER_PAYLOAD)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"email":["A user is already registered with this e-mail address."]}'
    assert len(mailoutbox) == 0


def test_can_have_multiple_users_with_the_same_unverified_email_but_only_one_can_verify_and_login(
        db, api_client, mailoutbox
):
    register_user(api_client, REGISTER_PAYLOAD)

    register_payload2 = {"password1": "test1234", "password2": "test1234", "email": REGISTER_PAYLOAD["email"]}
    response = register_user(api_client, register_payload2)

    assert response.status_code == status.HTTP_201_CREATED
    assert response.content.decode() == '{"detail":"Verification e-mail sent."}'

    users = get_user_model().objects.filter(email=REGISTER_PAYLOAD["email"])
    assert len(users) == 2

    assert len(mailoutbox) == 2
    keys = [extract_verify_email(email.body) for email in mailoutbox]

    # try to verify both users
    for key in keys:
        payload = {"key": key}
        response = api_client.post(reverse("rest_verify_email"), payload)

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {'detail': 'ok'}

    email_objs = EmailAddress.objects.filter(email=REGISTER_PAYLOAD["email"])
    assert len(email_objs) == 2

    assert email_objs[0].verified
    assert not email_objs[1].verified

    # Who can log in? Only the verified user.
    payload = {"email": REGISTER_PAYLOAD["email"], "password": REGISTER_PAYLOAD["password1"]}
    response = login(api_client, payload)
    assert response.status_code == status.HTTP_200_OK

    payload = {"email": register_payload2["email"], "password": register_payload2["password1"]}
    response = login(api_client, payload)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_registration_fails_due_to_missing_fields(db, api_client):
    response = register_user(api_client, {})

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.content.decode() == '{"email":["This field is required."],' \
                                        '"password1":["This field is required."],' \
                                        '"password2":["This field is required."]}'
