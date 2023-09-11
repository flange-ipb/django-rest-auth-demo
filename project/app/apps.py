from django.apps import AppConfig
from django.db.models.signals import pre_save

from project import settings
from project.app.signals import uuid_as_username


class AppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'project.app'
