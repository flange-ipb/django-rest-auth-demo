from allauth.account.signals import user_signed_up
from allauth.socialaccount.models import SocialAccount

from project.app.models import UserProfile
from tests.utils import register_and_verify, REGISTER_PAYLOAD, user_obj


def test__add_orcid_when_user_is_created_by_orcid_login_user__has_no_socialaccount(
        db, api_client, mailoutbox
):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
    user = user_obj(REGISTER_PAYLOAD["email"])
    assert user.socialaccount_set.count() == 0

    user_signed_up.send(sender=None, request=None, user=user)

    assert not hasattr(user, "userprofile")


def test__add_orcid_when_user_is_created_by_orcid_login_user__socialaccounts_have_no_orcid_provider(
        db, api_client, mailoutbox
):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
    user = user_obj(REGISTER_PAYLOAD["email"])
    SocialAccount.objects.create(user=user, provider="xyz", uid="12345")
    assert user.socialaccount_set.count() == 1

    user_signed_up.send(sender=None, request=None, user=user)

    assert not hasattr(user, "userprofile")


def test__add_orcid_when_user_is_created_by_orcid_login_user__orcid_socialaccount_has_no_uid(
        db, api_client, mailoutbox
):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
    user = user_obj(REGISTER_PAYLOAD["email"])
    SocialAccount.objects.create(user=user, provider="orcid")
    assert user.socialaccount_set.count() == 1

    user_signed_up.send(sender=None, request=None, user=user)

    assert not hasattr(user, "userprofile")


def test__add_orcid_when_user_is_created_by_orcid_login_user__with_orcid__user_has_no_userprofile(
        db, api_client, mailoutbox
):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
    user = user_obj(REGISTER_PAYLOAD["email"])
    orcid = "0000-0002-1825-0097"
    SocialAccount.objects.create(user=user, provider="orcid", uid=orcid)
    assert user.socialaccount_set.count() == 1
    assert UserProfile.objects.count() == 0

    user_signed_up.send(sender=None, request=None, user=user)

    assert user.userprofile.orcid == orcid


def test__add_orcid_when_user_is_created_by_orcid_login_user__with_orcid__user_has_userprofile(
        db, api_client, mailoutbox
):
    register_and_verify(api_client, REGISTER_PAYLOAD, mailoutbox)
    user = user_obj(REGISTER_PAYLOAD["email"])
    orcid = "0000-0002-1825-0097"
    SocialAccount.objects.create(user=user, provider="orcid", uid=orcid)
    assert user.socialaccount_set.count() == 1
    UserProfile.objects.create(user=user)
    assert UserProfile.objects.count() == 1

    user_signed_up.send(sender=None, request=None, user=user)

    assert user.userprofile.orcid == orcid
