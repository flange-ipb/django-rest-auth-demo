from django.apps import AppConfig


class AppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'project.app'

    def ready(self):
        # Implicitly connect signal handlers decorated with @receiver.
        from . import signals
