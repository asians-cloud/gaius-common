"""Public model-import surface for the shared ``gaius_common`` package.

Downstream services (gaius-domain, gaius-cert, gaius-route, ...) install this
package as a dependency and import shared ORM models from here, e.g.::

    from gaius_common.models import Routes, Services, FCMDevice

Keeping every consumer pointed at this single module means the underlying
model locations can move without touching the services.

Two groups of models are re-exported:

* **Kong gateway tables** — defined in :mod:`gaius_common.kong.models`
  (``managed = False`` mirrors of Kong's schema, routed to ``kong_database``).
* **FCMDevice** — the push-notification device registry from the third-party
  ``fcm_django`` app, routed to the ``common`` database. It is re-exported here
  rather than redefined; see the FCM section in ``README.md`` for the
  end-to-end (frontend → register → device row → celery push) flow.
"""

# Kong models are re-exported wholesale; there are ~25 of them and an explicit
# list would drift. ``kong.models`` defines no ``__all__``, so this pulls in
# every public name it declares (Routes, Services, Upstreams, Plugins, ...).
from gaius_common.kong.models import *  # noqa: F401,F403

# FCMDevice is re-exported explicitly so the dependency is obvious and does not
# rely on an incidental import being swept up by the wildcard above.
from fcm_django.models import FCMDevice  # noqa: F401
