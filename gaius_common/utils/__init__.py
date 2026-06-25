import logging

import requests
from django.conf import settings

logger = logging.getLogger()

# Bound the synchronous Keycloak round-trip so a hung Keycloak doesn't pin
# the worker thread for the global default (no timeout).
KEYCLOAK_REQUEST_TIMEOUT_SECONDS = 10


def update_lastname_keycloak(cname):
    # Imported lazily: a module-level model import runs at package-import time
    # (any `import gaius_common.utils.*` triggers this __init__), which raises
    # AppRegistryNotReady if the app registry isn't loaded yet.
    from django.contrib.auth.models import User

    try:
        user = User.objects.get(username__icontains=cname)
    except (User.DoesNotExist, User.MultipleObjectsReturned) as exc:
        logger.error("Cannot resolve a unique user for cname %s: %s", cname, exc)
        return

    oidc_profile = getattr(user, "oidc_profile", None)
    realm_obj = getattr(oidc_profile, "realm", None)
    realm = getattr(realm_obj, "name", None)
    if not realm:
        logger.error("User %s has no associated Keycloak realm", user.username)
        return

    token = requests.post(
        f"https://{settings.KEYCLOAK_CREDENTIALS[realm]['domain']}/auth/realms/{realm}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "admin-cli",
            "client_secret": settings.KEYCLOAK_CREDENTIALS[realm]["secret"],
        },
        timeout=KEYCLOAK_REQUEST_TIMEOUT_SECONDS,
    )
    if token.status_code != 200:
        logger.error(
            "Failed to obtain Keycloak token for realm %s (status %s)",
            realm,
            token.status_code,
        )
        return
    access_token = token.json().get("access_token")
    if not access_token:
        logger.error("Keycloak token response missing access_token for realm %s", realm)
        return
    response = requests.put(
        f"https://{settings.KEYCLOAK_CREDENTIALS[realm]['domain']}/auth/admin/realms/{realm}/users/{user.username}",
        json={"lastName": cname},
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        timeout=KEYCLOAK_REQUEST_TIMEOUT_SECONDS,
    )
    if response.status_code == 204:
        logger.info("Update lastname user in keycloak successfully")
    else:
        logger.info("Fail to update lastname user in keycloak")
