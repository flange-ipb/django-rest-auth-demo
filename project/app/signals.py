import uuid

from django.db.models.signals import pre_save
from django.dispatch import receiver

from project import settings


@receiver(pre_save, sender=settings.AUTH_USER_MODEL)
def uuid_as_username(sender, instance, **kwargs):
    if not instance.username:
        instance.username = str(uuid.uuid4())
        # TODO: consider https://docs.python.org/3/library/uuid.html#uuid.UUID.urn later ...
