import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    username = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)

    # need that or django.utils.encoding.force_str() will fail
    def __str__(self):
        return str(self.username)
