from django.apps import AppConfig


class CommonConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'gaius_common.common'

    def ready(self):
        import gaius_common.signals