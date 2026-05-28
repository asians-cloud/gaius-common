"""Deprecated module — kept only as a compatibility shim.

The Telegram sender used to live here (the module was misnamed; it never sent to
Slack except as a failure fallback, which has now been replaced by Discord).
Slack is fully retired. Import from ``gaius_common.utils.telegram`` instead:

    from gaius_common.utils.telegram import send_telegram_notification

This re-export keeps any straggling ``gaius_common.utils.slack`` import sites
working during the migration and can be removed once none remain.
"""
from gaius_common.utils.telegram import (  # noqa: F401
    send_telegram_notification,
    send_long_message_as_reply,
)
