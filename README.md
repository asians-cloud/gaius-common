# Gaius Common

This project is generated using [Cookiecutter Django](https://github.com/cookiecutter/cookiecutter-django), a framework for jumpstarting production-ready Django projects quickly.

## Installation instructions using poetry.

1. Create the pyproject.toml based on environment
```bash
cp pyproject.${ENVIRON}.toml pyproject.toml
```
This requires an environment variable called ENVIRON to be present (already a part of build.env.py)

2. Set the python version for poetry
```bash
poetry env use 3.9.0
```
This requires python 3.9.0 is already installed in the system.

3. Install the packages based on pyproject.toml
```bash
poetry install --without dev,test
```
This installs in a dedicated virtualenv for the project poetry creates in the background by itself. For local setup, include dev and test too.

4. Enter the poetry shell
```bash
poetry shell
```
This activates the virtualenv and allows interacting with our application using python manage.py <...>

## Setting Up the Project

1. Environment Variables
It is suggested to have build.uat.env.py file in the parent directory of this repository. Necessary env variables can then be loaded as follows.
```bash
cd ../
python build.uat.env.py
```
Following that, execute the first three commands returned by the above script. Note that if you are using a shell that colorizes grep, pass the `--color=never` flag as well.

2. Database Setup
```bash
python manage.py migrate
```

3. Create a superuser:
```bash
python manage.py createsuperuser
```

4. Static and Media Files
```bash
python manage.py collectstatic
```

5. Create media directory (not in use):
```bash
mkdir -p media
```

## Running the Development Server

Start the Django development server:

```bash
python manage.py runserver
```
The application will be available at http://127.0.0.1:8000/.
You can edit the port accordingly for the microservice and nginx configuration.

Start the celery worker in involved in the microservice:

```bash
celery -A config.celery_app worker -l info
```

## Running Tests
To run the tests for the application, use:
```bash
python manage.py test
```

## Common Management Commands

1. Creating new app:
```bash
python manage.py startapp <app_name>
```

2. Running Django shell:
```bash
python manage.py shell
```

3. Making migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

4. Adding / Upgrading new packages:
```bash
sh pkg_add.sh
```


## Architecture Notes

### Shared models (`gaius_common.models`)

`gaius-common` is installed as a dependency by the other gaius services
(gaius-domain, gaius-cert, gaius-route, ...). Those services import shared ORM
models from a single surface:

```python
from gaius_common.models import Routes, Services, FCMDevice
```

`gaius_common/models.py` aggregates two groups of models:

- **Kong gateway tables** — `managed = False` mirrors of Kong's schema, defined
  in `gaius_common/kong/models.py` and routed to `kong_database` by
  `KongDBRouter` (`gaius_common/dbrouter.py`).
- **`FCMDevice`** — the push-notification device registry from the third-party
  `fcm_django` app, routed to the `common` database by `AuthRouter`.

> **Note:** `FCMDevice` is *re-exported*, not redefined. Editing
> `gaius_common.models` or removing the `fcm_django` import there will break
> downstream services that do `from gaius_common.models import FCMDevice`.

### Push notifications (FCM)

This package **owns the `fcm_django_fcmdevice` table** (in the shared `common`
DB); the actual push logic lives in the consuming services. The feature is
live in production. End-to-end flow:

1. **Register** — the frontend (gaius-console) obtains a Firebase token and
   POSTs it to gaius-domain's `FCMRegisterView` (`domain/fcm-register/`), which
   creates/updates an `FCMDevice` row for the user.
2. **Send** — batch operations (clear cache, enable/disable HTTPS, import) run
   as celery tasks that call `send_user_fcm_notification(user_id, type)` in each
   service's `utils/redis_notification.py`. It looks up the user's latest
   `FCMDevice` and pushes via `pyfcm` using `FCM_DJANGO_SETTINGS['FCM_SERVER_KEY']`.
3. **In-app list** — on a successful push, the same function also writes the
   notification to Redis via `add_notification`; the frontend polls
   `domain/notify/` to render it. Note this in-app list is gated on the FCM
   send path, so a user with **no registered device gets neither** a push nor
   an in-app notification.

Relevant settings: `fcm_django` in `INSTALLED_APPS`, vendored migrations under
`gaius_common/contrib/fcm_django/migrations` (pinned via `MIGRATION_MODULES`),
`fcm_django` routed to `common` in `dbrouter.py`, and `FCM_APIKEY` /
`FCM_SERVER_KEY` env vars (the latter defined as `FCM_DJANGO_SETTINGS` in the
consuming services).

## Deployment

- Make sure any new environment variable you need is added to the env.yaml.j2 under /charts
- Make sure you add the associated Jira Key in your commit message.
- After publishing the code to either UAT, Staging or Main branch, trigger a deployment from Jenkins.

### Additional Resources
- [Django Documentation](https://docs.djangoproject.com/en/stable/)
- [Cookiecutter Django Documentation](https://cookiecutter-django.readthedocs.io/en/latest/)
- [Poetry Documentation](https://python-poetry.org/docs/)