"""Public model-import surface for the shared ``gaius_common`` package.

Downstream services (gaius-domain, gaius-cert, gaius-route, ...) install this
package as a dependency and import shared ORM models from here, e.g.::

    from gaius_common.models import Routes, Services

Keeping every consumer pointed at this single module means the underlying
model locations can move without touching the services.

Re-exports the **Kong gateway tables** — defined in :mod:`gaius_common.kong.models`
(``managed = False`` mirrors of Kong's schema, routed to ``kong_database``).

(FCMDevice was previously re-exported here; FCM has been decommissioned
platform-wide, so it and the ``fcm_django`` dependency were removed.)
"""

# Kong models are re-exported wholesale; there are ~25 of them and an explicit
# list would drift. ``kong.models`` defines no ``__all__``, so this pulls in
# every public name it declares (Routes, Services, Upstreams, Plugins, ...).
from gaius_common.kong.models import *  # noqa: F401,F403
