import re

import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

REGISTER_PAYLOAD = {"username": "test", "password1": "testtest", "password2": "testtest", "email": "test@test.example"}


class TestRegistration:
    def test_registration_workflow(self, db, api_client, mailoutbox):
        assert len(User.objects.all()) == 0

        response = register_user(api_client, REGISTER_PAYLOAD)

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data == {'detail': 'Verification e-mail sent.'}

        # user object was created
        assert len(User.objects.all()) == 1
        user = User.objects.get(pk=1)
        assert user.username == REGISTER_PAYLOAD["username"]
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

    def test_registration_fails_due_to_password_missmatch(self, db, api_client):
        payload = {"username": "test", "password1": "test1234", "password2": "testtest", "email": "test@test.example"}

        response = api_client.post(reverse("rest_register"), payload)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.content.decode() == '{"non_field_errors":["The two password fields didn\'t match."]}'

    def test_registration_fails_due_to_duplicate_username_and_email(self, db, api_client, mailoutbox):
        register_user(api_client, REGISTER_PAYLOAD)
        mailoutbox.clear()

        response = register_user(api_client, REGISTER_PAYLOAD)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.content.decode() == '{"username":["A user with that username already exists."],' \
                                            '"email":["A user is already registered with this e-mail address."]}'
        assert len(mailoutbox) == 0

    def test_registration_fails_due_to_missing_fields(self, db, api_client):
        response = register_user(api_client, {})

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.content.decode() == '{"username":["This field is required."],' \
                                            '"email":["This field is required."],' \
                                            '"password1":["This field is required."],' \
                                            '"password2":["This field is required."]}'


class TestResendEmailVerification:
    def test_resend_email_verification_workflow(self, db, api_client, mailoutbox):
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
    def test_no_resend_because_email_is_already_verified(self, db, api_client, mailoutbox):
        register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
        mailoutbox.clear()

        payload = {"email": REGISTER_PAYLOAD["email"]}
        response = api_client.post(reverse("rest_resend_email"), payload)

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {'detail': 'ok'}
        assert len(mailoutbox) == 0

    # cannot enumerate email addresses
    def test_no_resend_due_to_unknown_email(self, db, api_client, mailoutbox):
        payload = {"email": REGISTER_PAYLOAD["email"]}
        response = api_client.post(reverse("rest_resend_email"), payload)

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {'detail': 'ok'}
        assert len(mailoutbox) == 0

    def test_resend_fails_due_to_missing_field(self, db, api_client, mailoutbox):
        response = api_client.post(reverse("rest_resend_email"), payload={})

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.content.decode() == '{"email":["This field is required."]}'


class TestLogin:
    def test_can_login_with_email(self, db, api_client, mailoutbox):
        register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
        assert User.objects.get(pk=1).last_login is None

        payload = {"email": REGISTER_PAYLOAD["email"], "password": REGISTER_PAYLOAD["password1"]}
        response = login(api_client, payload)

        assert response.status_code == status.HTTP_200_OK

        # User's last_login field is NOT updated!
        # see https://github.com/iMerica/dj-rest-auth/issues/531
        assert User.objects.get(pk=1).last_login is None

        # validate access token
        access_token = response.data["access"]
        assert access_token is not None
        at_obj = AccessToken(access_token)
        at_obj.verify()
        at_obj.verify_token_type()
        assert at_obj.get("user_id") == 1

        # validate refresh token
        refresh_token = response.data["refresh"]
        assert refresh_token is not None
        rt_obj = RefreshToken(refresh_token)
        rt_obj.verify()
        rt_obj.verify_token_type()
        assert rt_obj.get("user_id") == 1

        assert response.data["user"] == {'pk': 1,
                                         'username': REGISTER_PAYLOAD["username"],
                                         'email': REGISTER_PAYLOAD["email"],
                                         'first_name': '',
                                         'last_name': ''}

    def test_cannot_login_with_username(self, db, api_client, mailoutbox):
        register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)

        payload = {"username": REGISTER_PAYLOAD["username"], "password": REGISTER_PAYLOAD["password1"]}
        response = login(api_client, payload)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.content.decode() == '{"non_field_errors":["Must include \\"email\\" and \\"password\\"."]}'

    def test_cannot_login_with_wrong_password(self, db, api_client, mailoutbox):
        register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)

        payload = {"email": REGISTER_PAYLOAD["email"], "password": "wrong password"}
        response = login(api_client, payload)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.content.decode() == '{"non_field_errors":["Unable to log in with provided credentials."]}'

    def test_inactive_user_cannot_login(self, db, api_client, mailoutbox):
        register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)

        user = User.objects.get(pk=1)
        user.is_active = False
        user.save()

        payload = {"email": REGISTER_PAYLOAD["email"], "password": REGISTER_PAYLOAD["password1"]}
        response = login(api_client, payload)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.content.decode() == '{"non_field_errors":["Unable to log in with provided credentials."]}'


class TestLogout:
    def test_logout_refresh_token_gets_blacklisted(self, db, api_client, mailoutbox):
        access_token, refresh_token = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
        rt_obj = RefreshToken(refresh_token)
        rt_obj.check_blacklist()

        response = logout(api_client, access_token, refresh_token)

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {"detail": "Successfully logged out."}

        with pytest.raises(TokenError):
            rt_obj = RefreshToken(refresh_token)
            rt_obj.check_blacklist()

    def test_after_logout_access_token_is_still_valid(self, db, api_client, mailoutbox):
        access_token, refresh_token = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
        logout(api_client, access_token, refresh_token)

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


class TestUserEndpoint:
    def test_change_user_info(self, db, api_client, mailoutbox):
        access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
        headers = auth_header(access_token)

        payload = {"username": "user123", "first_name": "firstname", "last_name": "lastname"}
        response = api_client.put(reverse("rest_user_details"), payload, headers=headers)

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {'pk': 1, 'username': 'user123', 'email': 'test@test.example',
                                 'first_name': 'firstname', 'last_name': 'lastname'}

    def test_user_cannot_change_email(self, db, api_client, mailoutbox):
        access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
        headers = auth_header(access_token)
        user_before = api_client.get(reverse("rest_user_details"), headers=headers).data

        payload = {"email": "abc@def.example"}
        response = api_client.patch(reverse("rest_user_details"), payload, headers=headers)

        assert response.status_code == status.HTTP_200_OK
        user_after = api_client.get(reverse("rest_user_details"), headers=headers).data
        assert user_after == user_before

    def test_cannot_delete_user(self, db, api_client, mailoutbox):
        access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
        headers = auth_header(access_token)

        response = api_client.delete(reverse("rest_user_details"), headers=headers)

        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


class TestPasswordReset:
    def test_password_reset_via_email(self, db, api_client, mailoutbox):
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

    def test_cannot_reuse_password_reset_confirm_token(self, db, api_client, mailoutbox):
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

    def test_cannot_reset_password_of_other_user_with_token(self, db, api_client, mailoutbox):
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
    def test_can_enumerate_user_ids_with_password_reset_confirm(self, db, api_client, mailoutbox):
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

    def test_password_reset_with_unknown_email_address_does_not_send_email(self, db, api_client, mailoutbox):
        payload = {"email": REGISTER_PAYLOAD["email"]}

        response = api_client.post(reverse("rest_password_reset"), payload)

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {'detail': 'Password reset e-mail has been sent.'}
        assert len(mailoutbox) == 0

    def test_password_reset_confirm_view_does_nothing(self, db, requests_client):
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


class TestPasswordChange:
    def test_password_change_successful(self, db, api_client, mailoutbox):
        access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
        headers = auth_header(access_token)
        new_pw = "test1234"
        old_pw_in_db = User.objects.get(pk=1).password

        payload = {"new_password1": new_pw, "new_password2": new_pw, "old_password": REGISTER_PAYLOAD["password1"]}
        response = api_client.post(reverse("rest_password_change"), payload, headers=headers)

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {'detail': 'New password has been saved.'}

        # password was changed in the database
        assert User.objects.get(pk=1).password != old_pw_in_db

    def test_password_change_fails_due_to_wrong_old_password(self, db, api_client, mailoutbox):
        access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
        headers = auth_header(access_token)
        new_pw = "test1234"
        old_pw_in_db = User.objects.get(pk=1).password

        payload = {"new_password1": new_pw, "new_password2": new_pw, "old_password": "wrong password"}
        response = api_client.post(reverse("rest_password_change"), payload, headers=headers)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.content.decode() == '{"old_password":' \
                                            '["Your old password was entered incorrectly. Please enter it again."]}'

        # password wasn't changed in the database
        assert User.objects.get(pk=1).password == old_pw_in_db

    def test_password_change_fails_due_to_new_password_mismatch(self, db, api_client, mailoutbox):
        access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
        headers = auth_header(access_token)
        old_pw_in_db = User.objects.get(pk=1).password

        payload = {"new_password1": "test1234", "new_password2": "1234test",
                   "old_password": REGISTER_PAYLOAD["password1"]}
        response = api_client.post(reverse("rest_password_change"), payload, headers=headers)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.content.decode() == '{"new_password2":["The two password fields didn’t match."]}'

        # password wasn't changed in the database
        assert User.objects.get(pk=1).password == old_pw_in_db


class TestVerifyJWT:
    def test_verify_valid_tokens(self, db, api_client, mailoutbox):
        tokens = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)

        for token in tokens:
            payload = {"token": token}
            response = api_client.post(reverse("token_verify"), payload)

            assert response.status_code == status.HTTP_200_OK
            assert response.data == {}

    def test_verify_blacklisted_token(self, db, api_client, mailoutbox):
        access_token, refresh_token = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)
        logout(api_client, access_token, refresh_token)

        payload = {"token": refresh_token}
        response = api_client.post(reverse("token_verify"), payload)

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {}

    def test_verify_invalid_token(self, db, api_client, mailoutbox):
        access_token, _ = register_and_login(api_client, REGISTER_PAYLOAD, mailoutbox)

        # manipulate the signature block
        invalid_token = access_token[:-5] + access_token[-4:]
        assert access_token != invalid_token

        payload = {"token": invalid_token}
        response = api_client.post(reverse("token_verify"), payload)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.content.decode() == '{"detail":"Token is invalid or expired","code":"token_not_valid"}'


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


def logout(client, access_token, refresh_token):
    headers = auth_header(access_token)
    payload = {"refresh": refresh_token}
    return client.post(reverse("rest_logout"), payload, headers=headers)


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def extract_email_verify_email(email):
    return re.search(r"account-confirm-email/(?P<key>[-:\w]+)", email).group("key")


def extract_password_reset_email(email):
    m = re.search(
        r"password-reset/confirm/(?P<uid>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,32})",
        email
    )
    return m.group("uid"), m.group("token")
