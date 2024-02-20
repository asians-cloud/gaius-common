import requests
from django.conf import settings

from telegram.error import TelegramError


def send_slack_notification(message):
    slack_webhook_url = settings.SLACK_WEBHOOK_URL
    payload = {
        "text": message
    }
    response = requests.post(slack_webhook_url, json=payload)        
    return True if response.status_code == 200 else False


def send_telegram_notification(bot, chat_id, message, parse_mode=None, disable_web_page_preview=False, timeout=None):
    try:
        bot.send_message(chat_id=chat_id, text=message, parse_mode=parse_mode, disable_web_page_preview=disable_web_page_preview, timeout=timeout)
        return True
    except TelegramError as e:
        try:
            bot.send_message(chat_id=chat_id, text=message, parse_mode=parse_mode, disable_web_page_preview=disable_web_page_preview, timeout=timeout)
            return True
        except TelegramError as e:
            send_slack_notification(message=message)
