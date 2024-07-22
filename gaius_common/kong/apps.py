from django.apps import AppConfig


class KongConfig(AppConfig):
    name = 'gaius_common.kong'

    def ready(self):
        import gaius_common.signals
