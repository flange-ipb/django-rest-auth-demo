import uuid

from allauth.account.signals import user_signed_up
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.orcid.provider import extract_from_dict
from django.conf import settings
from django.db.models.signals import pre_save
from django.dispatch import receiver

from project.app.models import UserProfile


@receiver(pre_save, sender=settings.AUTH_USER_MODEL)
def uuid_as_username(sender, instance, **kwargs):
    if not instance.username:
        instance.username = str(uuid.uuid4())
        # TODO: consider https://docs.python.org/3/library/uuid.html#uuid.UUID.urn later ...


# Signal 'social_account_added' is not sent when a social login creates a new user,
# see https://github.com/pennersr/django-allauth/issues/1781
#
# Not sure if it's wise to also update the ORCID every time an existing user logs
# in or connects to the social provider ...
@receiver(user_signed_up)
def add_orcid_when_user_is_created_by_orcid_login(sender, request, user, **kwargs):
    social_account: SocialAccount = user.socialaccount_set.filter(provider="orcid").first()
    if not social_account:
        return

    orcid = social_account.uid
    if not orcid:
        return

    user_profile = user.userprofile if hasattr(user, "userprofile") else UserProfile(user=user)
    user_profile.orcid = orcid
    user_profile.save()


def extract_orcid_from_data(data):
    return extract_from_dict(data, ["orcid-identifier", "path"])
