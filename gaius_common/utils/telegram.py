import asyncio

import telegram
from telegram import constants


def _split_message(notify_message):
    """Split a long message into chunks under MAX_MESSAGE_LENGTH, preferring
    to break on newlines, then sentence boundaries, then a hard cut."""
    msg = notify_message
    sub_msgs = []
    while len(msg):
        split_point = msg[:constants.MAX_MESSAGE_LENGTH].rfind('\n')
        if split_point != -1:
            sub_msgs.append(msg[:split_point])
            msg = msg[split_point + 1:]
        else:
            split_point = msg[:constants.MAX_MESSAGE_LENGTH].rfind('. ')
            if split_point != -1:
                sub_msgs.append(msg[:split_point + 1])
                msg = msg[split_point + 2:]
            else:
                sub_msgs.append(msg[:constants.MAX_MESSAGE_LENGTH])
                msg = msg[constants.MAX_MESSAGE_LENGTH:]
    return sub_msgs


def send_long_message_as_reply(bot, notify_message, chat_id, parse_mode):
    if int(telegram.__version__.split(".")[0]) < 20:
        # python-telegram-bot v13 (sync) path.
        if len(notify_message) > constants.MAX_MESSAGE_LENGTH:
            sub_msgs = _split_message(notify_message)
            message = bot.send_message(chat_id=chat_id, text=sub_msgs[0],
                                       parse_mode=parse_mode, disable_web_page_preview=True, timeout=35).result()
            for send_msg in sub_msgs[1:]:
                try:
                    message.reply_html(send_msg)
                except Exception:
                    import time
                    time.sleep(15)
        else:
            bot.send_message(chat_id=chat_id, text=notify_message, parse_mode=parse_mode,
                             disable_web_page_preview=True, timeout=35).result()
        return

    # python-telegram-bot v20+ (async) path. send_message/reply_html are
    # coroutines and the bot must be initialized, so drive them inside
    # `async with bot:`. `disable_web_page_preview`/`timeout` were removed.
    from telegram import LinkPreviewOptions

    async def _run():
        no_preview = LinkPreviewOptions(is_disabled=True)
        async with bot:
            if len(notify_message) > constants.MAX_MESSAGE_LENGTH:
                sub_msgs = _split_message(notify_message)
                message = await bot.send_message(
                    chat_id=chat_id, text=sub_msgs[0], parse_mode=parse_mode,
                    link_preview_options=no_preview,
                )
                for send_msg in sub_msgs[1:]:
                    try:
                        await message.reply_html(send_msg)
                    except Exception:
                        await asyncio.sleep(15)
            else:
                await bot.send_message(
                    chat_id=chat_id, text=notify_message, parse_mode=parse_mode,
                    link_preview_options=no_preview,
                )

    asyncio.run(_run())
