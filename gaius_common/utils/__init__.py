import requests, logging
from django.conf import settings
from django.contrib.auth.models import User

logger = logging.getLogger()

def update_lastname_keycloak(cname):
    user = User.objects.get(username__icontains=cname)
    realm = user.oidc_profile.realm.name

    token = requests.post(f"https://{settings.KEYCLOAK_CREDENTIALS[realm]['domain']}/auth/realms/{realm}/protocol/openid-connect/token", data={'grant_type': 'client_credentials', 'client_id': 'admin-cli', 'client_secret': settings.KEYCLOAK_CREDENTIALS[realm]['secret']})
    access_token = token.json()['access_token']
    response = requests.put(f"https://{settings.KEYCLOAK_CREDENTIALS[realm]['domain']}/auth/admin/realms/{realm}/users/{user.username}", json={"lastName": cname}, headers={'Authorization': f"Bearer {access_token}", 'Content-Type': 'application/json'})
    if response.status_code == 204:
        logger.info('Update lastname user in keycloak successfully')
    else:
        logger.info('Fail to update lastname user in keycloak')
