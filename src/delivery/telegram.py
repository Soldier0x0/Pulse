"""Telegram delivery client."""

from __future__ import annotations

from telegram import Bot
from telegram.constants import ParseMode


async def send_telegram_alert(bot_token: str, chat_id: str, text: str, pin: bool = False) -> None:
    """Send HTML alert and optionally pin for critical severities."""

    bot = Bot(token=bot_token)
    sent = await bot.send_message(chat_id=chat_id, text=text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    if pin:
        await bot.pin_chat_message(chat_id=chat_id, message_id=sent.message_id, disable_notification=True)
