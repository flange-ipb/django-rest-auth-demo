import allauth
from django.db import models


class UserProfile(models.Model):
    user = models.OneToOneField(allauth.app_settings.USER_MODEL, on_delete=models.CASCADE)
    orcid = models.CharField(max_length=19)
