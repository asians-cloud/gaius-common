class AuthRouter:
    """
    A router to control all database operations on models in the
    auth and contenttypes applications.
    """
    route_app_labels = {'auth', 'admin', 'sites', 'authtoken', 'sessions', 'contenttypes',  'django_keycloak', 'django_celery_results', 'django_celery_beat',
                        'fcm_django' ,'common'}

    def db_for_read(self, model, **hints):
        """
        Attempts to read common and contenttypes models go to auth_db.
        """
        if model._meta.app_label in self.route_app_labels:
            return 'common'
        return None

    def db_for_write(self, model, **hints):
        """
        Attempts to write common and contenttypes models go to auth_db.
        """
        if model._meta.app_label in self.route_app_labels:
            return 'common'
        return None

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if a model in the common or contenttypes apps is
        involved.
        """
        if (
            obj1._meta.app_label in self.route_app_labels or
            obj2._meta.app_label in self.route_app_labels
        ):
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Make sure the common and contenttypes apps only appear in the
        'common_db' database.
        """
        if app_label in self.route_app_labels:
            return db == 'common'
        return None


class KongDBRouter(object):

    route_app_labels = {"kong"}

    def db_for_read(self, model, **hints):
        """
        Attempts to read gaius_kong models go to "kong_database".
        """
        if model._meta.app_label in self.route_app_labels:
            return "kong_database"
        return None

    def db_for_write(self, model, **hints):
        """
        Attempts to write auth and contenttypes models go to auth_db.
        """
        if model._meta.app_label in self.route_app_labels:
            return "kong_database"
        return None

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if a model in the kong app is involved.
        """
        if (
            obj1._meta.app_label in self.route_app_labels
            or obj2._meta.app_label in self.route_app_labels
        ):
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Make sure the kong app only appear in the '"kong_database"' database.
        """
        return None
