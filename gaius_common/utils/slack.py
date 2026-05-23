import asyncio
import traceback

import requests
import telegram
from django.conf import settings


SLACK_REQUEST_TIMEOUT_SECONDS = 10


def send_slack_notification(message):
    slack_webhook_url = settings.SLACK_WEBHOOK_URL
    payload = {
        "text": message
    }
    response = requests.post(
        slack_webhook_url, json=payload, timeout=SLACK_REQUEST_TIMEOUT_SECONDS
    )
    return True if response.status_code == 200 else False


def _ptb_is_async():
    """python-telegram-bot made Bot methods coroutines in v20."""
    return int(telegram.__version__.split(".")[0]) >= 20


def _parse_chat_id(chat_id):
    """
    Supports:
        -1001234567890
        "-1001234567890"
        "-1001234567890_74"

    Returns:
        (chat_id, message_thread_id)
    """

    if isinstance(chat_id, str) and "_" in chat_id:
        base_chat_id, thread_id = chat_id.split("_", 1)
        return int(base_chat_id), int(thread_id)

    return int(chat_id), None


def _send_once(bot, chat_id, message, parse_mode, disable_web_page_preview, timeout):
    """Send one message, compatible with python-telegram-bot v13 and v20+.

    On v20+ Bot.send_message is a coroutine and the bot must be initialized
    before use, so we drive it on a fresh event loop inside `async with bot:`
    (the supported pattern for a standalone Bot, e.g. from a Celery worker).

    Supports Telegram forum topics automatically via:
        -1001234567890_74
    """

    parsed_chat_id, message_thread_id = _parse_chat_id(chat_id)

    kwargs = {
        "chat_id": parsed_chat_id,
        "text": message,
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

            kwargs["link_preview_options"] = LinkPreviewOptions(
                is_disabled=True
            )

        async with bot:
            await bot.send_message(**kwargs)

    asyncio.run(_send())


def send_telegram_notification(
    bot,
    chat_id,
    message,
    parse_mode=None,
    disable_web_page_preview=False,
    timeout=None
):
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

    except Exception:
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

        except Exception as e:
            message = f"""
                {message}

                *Error:*
                {str(e)}

                *File Path:*
                {traceback.extract_tb(e.__traceback__)[-1]}

                *Traceback:*
                {traceback.format_exc()}
            """

            send_slack_notification(message=message)

            return False
