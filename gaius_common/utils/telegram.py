"""Centralised Telegram notification helpers for every Gaius service.

All notifications go to ONE Telegram forum group, addressed per topic via the
``-100<group>_<message_thread_id>`` syntax that :func:`send_telegram_notification`
understands. Slack and Discord have been retired; on a failed Telegram send we
fall back to a Google Chat space webhook (silent no-op until the
``NOTIFICATION_GCHAT_FALLBACK_WEBHOOK`` env/setting is configured — see
``_gchat_fallback``).

This module is the canonical home for the sender (it used to live, misnamed, in
``gaius_common.utils.slack``). Each service maps its own ``BotGroup`` logical
names onto the :class:`Topic` constants below, so existing call sites
(``send_telegram_notification(bot, BotGroup.X, msg)``) keep working unchanged —
only the destination moved.
"""

import asyncio
import logging
import os
import threading
import time
import traceback

import requests
import telegram
from django.conf import settings
from telegram import constants

# Telegram caps a text message at 4096 chars. The constant moved between
# python-telegram-bot majors (v13: ``MAX_MESSAGE_LENGTH``; v20+:
# ``constants.MessageLimit.MAX_TEXT_LENGTH``), so resolve it defensively and
# fall back to the documented hard limit.
try:
    MAX_MESSAGE_LENGTH = int(constants.MessageLimit.MAX_TEXT_LENGTH)
except AttributeError:  # python-telegram-bot < 20
    MAX_MESSAGE_LENGTH = int(getattr(constants, "MAX_MESSAGE_LENGTH", 4096))


def _truncate_for_telegram(message):
    """Guarantee a single message fits Telegram's limit.

    Keeps the head and tail and elides the middle, because for tracebacks both
    ends matter: the head carries the request/context and the tail the actual
    exception. Truncating (rather than splitting into N sends) keeps a noisy
    error log to one message and, crucially, prevents the "Message is too long"
    BadRequest that otherwise forces the Google Chat fallback.
    """
    if len(message) <= MAX_MESSAGE_LENGTH:
        return message
    marker = "\n\n[... truncated ...]\n\n"
    budget = MAX_MESSAGE_LENGTH - len(marker)
    head = budget // 2
    tail = budget - head
    return message[:head] + marker + message[-tail:]


# --- Notification group + topics -------------------------------------------
#
# Single source of truth for where notifications land. The group id can be
# overridden per environment via the NOTIFICATION_TELEGRAM_GROUP env var, but
# the topic thread ids are stable infrastructure constants and live here so we
# no longer scatter ~16 TGBOT_GROUP_* env vars across every service/chart.
#
# Read from os.environ (not django settings): this module is imported from
# services' settings modules, where django.conf.settings isn't configured yet.
NOTIFICATION_GROUP_ID = os.environ.get("NOTIFICATION_TELEGRAM_GROUP", "-1003746463771")


def _topic(thread_id):
    """Build a forum-topic chat id understood by send_telegram_notification."""
    return f"{NOTIFICATION_GROUP_ID}_{thread_id}"


class Topic:
    """message_thread_id map for group ``NOTIFICATION_GROUP_ID``.

    Tiers (for mute guidance): P1 critical, P2 high, P3 informational.
    """

    # P1 — critical (never mute)
    CRITICAL_ERRORS = _topic(3782)
    EMERGENCY = _topic(3783)
    PAYMENTS = _topic(3784)

    # P2 — high
    APP_ERRORS = _topic(3785)
    ATTACK_MONITOR = _topic(3786)
    PROTECTION_MONITOR = _topic(3787)
    CERTIFICATES = _topic(3788)
    CROWDSEC_BANS = _topic(3789)

    # P3 — informational (mute-friendly)
    USER = _topic(3790)
    UPSTREAM_MONITOR = _topic(3791)
    CDN = _topic(3792)
    SA_OPERATIONS = _topic(3793)
    TOOLS = _topic(3794)


# --- python-telegram-bot v13/v20 compatibility ------------------------------


def _ptb_is_async():
    """python-telegram-bot made Bot methods coroutines in v20."""
    return int(telegram.__version__.split(".")[0]) >= 20


def _parse_chat_id(chat_id):
    """
    Supports:
        -1001234567890
        "-1001234567890"
        "-1001234567890_74"   (forum topic / message_thread_id)

    Returns:
        (chat_id, message_thread_id)
    """

    if isinstance(chat_id, str) and "_" in chat_id:
        base_chat_id, thread_id = chat_id.split("_", 1)
        return int(base_chat_id), int(thread_id)

    return int(chat_id), None


def chat_id_of(topic):
    """Return just the integer group chat id for a Topic address.

    Topic constants encode the forum thread as ``"<group>_<thread>"``; callers
    that need to compare an *incoming* update's ``chat.id`` (the bare group id)
    — e.g. the interactive command bots — should use this instead of
    ``int(Topic.X)``, which would raise on the underscore.
    """
    base_chat_id, _ = _parse_chat_id(topic)
    return base_chat_id


def thread_id_of(topic):
    """Return the message_thread_id for a Topic address (None if not a topic)."""
    _, thread_id = _parse_chat_id(topic)
    return thread_id


def message_in_topic(message, topic):
    """True if an incoming Telegram ``message`` belongs to the given Topic.

    Used by the interactive command bots to gate which forum topic a command is
    answered in: matches BOTH the group chat id and the forum thread
    (``message_thread_id``). Safe on python-telegram-bot versions / messages
    without ``message_thread_id`` (treated as ``None``) — a command in the
    group's "General" area only matches a Topic that has no thread.
    """
    chat_id = getattr(message, "chat_id", None)
    if chat_id is None:
        chat = getattr(message, "chat", None)
        chat_id = getattr(chat, "id", None)
    thread_id = getattr(message, "message_thread_id", None)
    return chat_id == chat_id_of(topic) and thread_id == thread_id_of(topic)


def _send_once(bot, chat_id, message, parse_mode, disable_web_page_preview, timeout):
    """Send one message, compatible with python-telegram-bot v13 and v20+.

    On v20+ Bot.send_message is a coroutine and the bot must be initialized
    before use, so we drive it on a fresh event loop inside ``async with bot:``
    (the supported pattern for a standalone Bot, e.g. from a Celery worker).

    Supports Telegram forum topics automatically via ``-1001234567890_74``.
    """

    parsed_chat_id, message_thread_id = _parse_chat_id(chat_id)

    kwargs = {
        "chat_id": parsed_chat_id,
        "text": _truncate_for_telegram(message),
        "parse_mode": parse_mode,
    }

    if message_thread_id is not None:
        kwargs["message_thread_id"] = message_thread_id

    if not _ptb_is_async():
        kwargs["disable_web_page_preview"] = disable_web_page_preview
        kwargs["timeout"] = timeout

        bot.send_message(**kwargs)
        return

    async def _send():
        if disable_web_page_preview:
            from telegram import LinkPreviewOptions

            kwargs["link_preview_options"] = LinkPreviewOptions(is_disabled=True)

        async with bot:
            await bot.send_message(**kwargs)

    asyncio.run(_send())


# --- Long-message splitting (used by gaius-domain traffic alerts) -----------


def _split_message(notify_message):
    """Split a long message into chunks under MAX_MESSAGE_LENGTH, preferring
    to break on newlines, then sentence boundaries, then a hard cut."""
    msg = notify_message
    sub_msgs = []
    while len(msg):
        split_point = msg[:MAX_MESSAGE_LENGTH].rfind("\n")
        if split_point != -1:
            sub_msgs.append(msg[:split_point])
            msg = msg[split_point + 1 :]
        else:
            split_point = msg[:MAX_MESSAGE_LENGTH].rfind(". ")
            if split_point != -1:
                sub_msgs.append(msg[: split_point + 1])
                msg = msg[split_point + 2 :]
            else:
                sub_msgs.append(msg[:MAX_MESSAGE_LENGTH])
                msg = msg[MAX_MESSAGE_LENGTH:]
    return sub_msgs


def send_long_message_as_reply(bot, notify_message, chat_id, parse_mode):
    # chat_id may be a Topic address ("<group>_<thread>"); split it so the first
    # message lands in the right forum topic. Follow-up chunks are replies and
    # inherit the thread automatically.
    parsed_chat_id, message_thread_id = _parse_chat_id(chat_id)
    thread_kwargs = {}
    if message_thread_id is not None:
        thread_kwargs["message_thread_id"] = message_thread_id

    if int(telegram.__version__.split(".")[0]) < 20:
        # python-telegram-bot v13 (sync) path.
        if len(notify_message) > MAX_MESSAGE_LENGTH:
            sub_msgs = _split_message(notify_message)
            message = bot.send_message(
                chat_id=parsed_chat_id,
                text=sub_msgs[0],
                parse_mode=parse_mode,
                disable_web_page_preview=True,
                timeout=35,
                **thread_kwargs,
            ).result()
            for send_msg in sub_msgs[1:]:
                try:
                    message.reply_html(send_msg)
                except Exception:
                    import time

                    time.sleep(15)
        else:
            bot.send_message(
                chat_id=parsed_chat_id,
                text=notify_message,
                parse_mode=parse_mode,
                disable_web_page_preview=True,
                timeout=35,
                **thread_kwargs,
            ).result()
        return

    # python-telegram-bot v20+ (async) path. send_message/reply_html are
    # coroutines and the bot must be initialized, so drive them inside
    # ``async with bot:``. disable_web_page_preview/timeout were removed.
    from telegram import LinkPreviewOptions

    async def _run():
        no_preview = LinkPreviewOptions(is_disabled=True)
        async with bot:
            if len(notify_message) > MAX_MESSAGE_LENGTH:
                sub_msgs = _split_message(notify_message)
                message = await bot.send_message(
                    chat_id=parsed_chat_id,
                    text=sub_msgs[0],
                    parse_mode=parse_mode,
                    link_preview_options=no_preview,
                    **thread_kwargs,
                )
                for send_msg in sub_msgs[1:]:
                    try:
                        await message.reply_html(send_msg)
                    except Exception:
                        await asyncio.sleep(15)
            else:
                await bot.send_message(
                    chat_id=parsed_chat_id,
                    text=notify_message,
                    parse_mode=parse_mode,
                    link_preview_options=no_preview,
                    **thread_kwargs,
                )

    asyncio.run(_run())


# --- Google Chat fallback (silent until a webhook is configured) ------------

_GCHAT_REQUEST_TIMEOUT_SECONDS = 10


def _gchat_fallback(message):
    """Last-resort delivery when Telegram is unreachable.

    Posts to a Google Chat space via an incoming-webhook URL read from
    ``settings.NOTIFICATION_GCHAT_FALLBACK_WEBHOOK`` (or the env var of the same
    name). Until that is set this is a silent no-op, so a Telegram outage
    degrades quietly rather than erroring. Never raises — it is only ever called
    from an except branch.
    """
    webhook_url = getattr(
        settings, "NOTIFICATION_GCHAT_FALLBACK_WEBHOOK", ""
    ) or os.environ.get("NOTIFICATION_GCHAT_FALLBACK_WEBHOOK", "")
    if not webhook_url:
        return False
    try:
        requests.post(
            webhook_url,
            json={"text": message},
            timeout=_GCHAT_REQUEST_TIMEOUT_SECONDS,
        )
        return True
    except Exception:
        return False


def _telegram_error_details(exc):
    """Summarise a failed Telegram send for the fallback report.

    python-telegram-bot raises typed errors (``BadRequest``, ``Forbidden`` …)
    but does not attach the raw HTTP status to the exception object, so we map
    the well-known error classes to the status Telegram returned. Returns a
    short line like ``HTTP 400 BadRequest: Can't parse entities: ...`` — the API
    status code plus the reason Telegram gave — so an operator can tell a
    message-formatting bug (400) from an auth (401/403) or rate-limit (429)
    problem at a glance instead of reading the traceback.
    """
    name = type(exc).__name__
    reason = str(exc) or repr(exc)

    # Some PTB versions (or wrapped HTTP errors) expose the code directly.
    status = None
    for attr in ("status_code", "code"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            status = value
            break

    if status is None:
        try:
            from telegram import error as tg_error
        except Exception:
            tg_error = None
        if tg_error is not None:
            # Most specific classes first so a subclass isn't shadowed by its base.
            status_by_class = [
                ("RetryAfter", 429),
                ("Conflict", 409),
                ("Forbidden", 403),
                ("Unauthorized", 401),
                ("InvalidToken", 401),
                ("ChatMigrated", 400),
                ("BadRequest", 400),
                ("TimedOut", 504),
            ]
            for cls_name, code in status_by_class:
                cls = getattr(tg_error, cls_name, None)
                if cls is not None and isinstance(exc, cls):
                    status = code
                    break

    status_text = "HTTP %d" % status if status is not None else "no HTTP status"
    return "%s %s: %s" % (status_text, name, reason)


def _is_parse_entities_error(exc):
    """True when Telegram rejected the message for bad parse_mode markup.

    A ``BadRequest: Can't parse entities`` is deterministic: it depends only on
    the message text + parse_mode, so retrying the identical call always fails
    the same way and needlessly degrades to the Google Chat fallback. Detecting
    it lets the retry drop parse_mode and still land the message in Telegram.
    """
    try:
        from telegram import error as tg_error

        bad_request = getattr(tg_error, "BadRequest", None)
        if bad_request is not None and not isinstance(exc, bad_request):
            return False
    except Exception:
        pass
    return "can't parse entities" in str(exc).lower()


def send_telegram_notification(
    bot, chat_id, message, parse_mode=None, disable_web_page_preview=False, timeout=None
):
    """Send a notification to Telegram (one retry), falling back to Google Chat.

    ``chat_id`` is normally a :class:`Topic` constant, e.g. ``Topic.PAYMENTS``.
    """
    try:
        _send_once(
            bot,
            chat_id,
            message,
            parse_mode,
            disable_web_page_preview,
            timeout,
        )
        return True

    except Exception as first_exc:
        # A parse-entities error is deterministic, so retrying the same HTML
        # fails identically. Drop parse_mode on the retry: the message still
        # reaches Telegram (markup shows as literal text) instead of degrading
        # all the way to the Google Chat fallback. Any other error retries as-is.
        retry_parse_mode = None if _is_parse_entities_error(first_exc) else parse_mode
        try:
            _send_once(
                bot,
                chat_id,
                message,
                retry_parse_mode,
                disable_web_page_preview,
                timeout,
            )
            return True

        except Exception as e:
            message = f"""
                {message}

                *Error:*
                {_telegram_error_details(e)}

                *File Path:*
                {traceback.extract_tb(e.__traceback__)[-1]}

                *Traceback:*
                {traceback.format_exc()}
            """

            _gchat_fallback(message)

            return False


# --- Logging handler: routes errors to the right notification topic ---------


class _RequestMetaFormatter(logging.Formatter):
    """Appends request user/IP/referer when a log record carries a request."""

    meta_attrs = ["REMOTE_ADDR", "HOSTNAME", "HTTP_REFERER"]

    def format(self, record):
        s = super().format(record)
        request = getattr(record, "request", None)
        if request is not None:
            try:
                s += f"\nUSER: {getattr(request, 'user', '')}"
                meta = getattr(request, "META", {}) or {}
                for attr in self.meta_attrs:
                    if attr in meta:
                        s += f"\n{attr}: {meta[attr]}"
            except Exception:
                pass
        return s


class TelegramLogHandler(logging.Handler):
    """Django logging handler that posts log records to a Telegram topic.

    Replaces the old per-service log handlers (the retired Discord one and the
    v13-only ``django_log_to_telegram.log.AdminTelegramHandler``). Configure one handler
    per level/topic, e.g. CRITICAL -> Topic.CRITICAL_ERRORS and
    ERROR -> Topic.APP_ERRORS, both pointed at the service's own bot token.

    Sends as plain text (no parse_mode) so raw tracebacks can't trip Telegram's
    HTML/Markdown parser. Failures degrade to the Google Chat fallback and never
    propagate back into logging, so there is no recursion risk.

    **Throttling/dedup:** repeats of the same error signature (logger + level +
    call site + message template) are suppressed within ``throttle_seconds``
    (default 60) so a hot error path can't flood the topic. The first send after
    a window appends a ``(+N similar suppressed …)`` note with the count dropped
    during the window. State is per-process and shared across handler instances.
    """

    # Process-wide throttle state (shared by all handler instances so the
    # network send happens outside the lock).
    _throttle_lock = threading.Lock()
    _last_sent = {}  # signature -> monotonic ts of last send
    _suppressed = {}  # signature -> count suppressed since last send

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.bot_token = kwargs.get("bot_token") or kwargs.get("bot_id")
        self.chat_id = kwargs.get("chat_id")
        self.service = kwargs.get("service", "")
        self.throttle_seconds = int(kwargs.get("throttle_seconds", 60))
        self.setFormatter(_RequestMetaFormatter())

    def _signature(self, record):
        # Group by call site + level + raw message template (not the formatted
        # message, which may carry per-event values), so identical errors collapse.
        return f"{record.name}:{record.levelno}:{record.pathname}:{record.lineno}:{str(record.msg)[:200]}"

    def emit(self, record):
        try:
            sig = self._signature(record)
            now = time.monotonic()
            with self._throttle_lock:
                last = self._last_sent.get(sig)
                if last is not None and (now - last) < self.throttle_seconds:
                    # Within the cooldown for this signature — count and drop.
                    self._suppressed[sig] = self._suppressed.get(sig, 0) + 1
                    return
                suppressed = self._suppressed.pop(sig, 0)
                self._last_sent[sig] = now

            bot = telegram.Bot(self.bot_token)
            prefix = f"[{self.service}] " if self.service else ""
            text = prefix + self.format(record)
            if suppressed:
                text += (
                    f"\n\n(+{suppressed} similar suppressed in the last "
                    f"{self.throttle_seconds}s)"
                )
            send_telegram_notification(
                bot,
                self.chat_id,
                text,
                parse_mode=None,
            )
        except Exception:
            # A logging handler must never raise.
            self.handleError(record)
