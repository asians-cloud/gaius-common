from telegram import constants


def send_long_message_as_reply(bot, notify_message, chat_id, parse_mode):
    if len(notify_message) > constants.MAX_MESSAGE_LENGTH:
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

        message = bot.send_message(chat_id=chat_id, text=sub_msgs[0],
                                   parse_mode=parse_mode, disable_web_page_preview=True, timeout=35).result()

        for send_msg in sub_msgs[1:]:
            try:
                message.reply_html(send_msg)
            except Exception as e:
                import time
                time.sleep(15)
    else:
        bot.send_message(chat_id=chat_id, text=notify_message, parse_mode=parse_mode, disable_web_page_preview=True,
                         timeout=35).result()
