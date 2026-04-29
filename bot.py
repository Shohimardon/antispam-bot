"""
Telegram Антиспам Бот — TezWeb.uz
==================================
Функции:
  - Удаляет сообщения с запрещёнными словами
  - Удаляет ссылки (http/https, t.me, @username)
  - Удаляет фото и видео от не-админов
  - Кикает нарушителя из группы
  - Администраторы управляют настройками через команды

Зависимости:
    pip install python-telegram-bot==20.7

Запуск:
    python bot.py
"""

import json
import logging
import os
import re
import asyncio
from pathlib import Path
from datetime import datetime

from telegram import Update, ChatMember, InlineKeyboardButton, InlineKeyboardMarkup, ChatPermissions
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# ──────────────────────────────────────────────
# Настройки
# ──────────────────────────────────────────────

BOT_TOKEN     = os.environ.get("BOT_TOKEN", "ВАШ_ТОКЕН_ЗДЕСЬ")
KEYWORDS_FILE = "keywords.json"
SETTINGS_FILE = "settings.json"

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Регулярки для ссылок и @упоминаний
URL_REGEX      = re.compile(r'(https?://\S+|www\.\S+|t\.me/\S+)', re.IGNORECASE)
MENTION_REGEX  = re.compile(r'@[a-zA-Z0-9_]{4,}')

# ──────────────────────────────────────────────
# Хранилище
# ──────────────────────────────────────────────

def load_keywords() -> set:
    if Path(KEYWORDS_FILE).exists():
        with open(KEYWORDS_FILE, "r", encoding="utf-8") as f:
            return set(json.load(f))
    return set()

def save_keywords(keywords: set) -> None:
    with open(KEYWORDS_FILE, "w", encoding="utf-8") as f:
        json.dump(list(keywords), f, ensure_ascii=False, indent=2)

def load_settings() -> dict:
    defaults = {
        "block_links":  True,
        "block_photos": True,
        "block_videos": True,
    }
    if Path(SETTINGS_FILE).exists():
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
            defaults.update(saved)
    return defaults

def save_settings(settings: dict) -> None:
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)

KEYWORDS: set  = load_keywords()
SETTINGS: dict = load_settings()

# ──────────────────────────────────────────────
# Вспомогательные функции
# ──────────────────────────────────────────────

async def is_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
        return member.status in (ChatMember.ADMINISTRATOR, ChatMember.OWNER)
    except Exception:
        return False

def contains_spam_word(text: str) -> str | None:
    text_lower = text.lower()
    for word in KEYWORDS:
        if word.lower() in text_lower:
            return word
    return None

def contains_link(text: str) -> bool:
    return bool(URL_REGEX.search(text) or MENTION_REGEX.search(text))

async def kick_user(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int) -> bool:
    """Кикает пользователя (ban + unban = кик)."""
    try:
        await context.bot.ban_chat_member(chat_id, user_id)
        await asyncio.sleep(1)
        await context.bot.unban_chat_member(chat_id, user_id)
        return True
    except Exception as e:
        logger.error("Не удалось кикнуть пользователя %s: %s", user_id, e)
        return False

async def delete_and_kick(update: Update, context: ContextTypes.DEFAULT_TYPE, reason: str) -> None:
    """Удаляет сообщение, кикает пользователя и уведомляет чат."""
    message = update.message
    user    = update.effective_user
    chat    = update.effective_chat
    name    = f"@{user.username}" if user.username else user.first_name

    # Удаляем сообщение
    try:
        await message.delete()
    except Exception as e:
        logger.error("Не удалось удалить сообщение: %s", e)

    # Кикаем
    kicked = await kick_user(context, chat.id, user.id)

    # Уведомление в чат
    kick_text = "guruhdan chiqarib yuborildi ✅" if kicked else "chiqarib bo'lmadi ⚠️"
    notice = await context.bot.send_message(
        chat_id=chat.id,
        text=(
            f"🚫 *{name}*, siz guruh qoidalarini buzgansiz!\n"
            f"📌 Sabab: {reason}\n"
            f"👢 Siz guruhdan chiqarib yuborldingiz."
        ),
        parse_mode="Markdown",
    )

    logger.info("Нарушитель %s кикнут из %s | причина: %s", name, chat.title or chat.id, reason)

    # Автоудаление уведомления через 10 секунд
    await asyncio.sleep(10)
    try:
        await notice.delete()
    except Exception:
        pass

# ──────────────────────────────────────────────
# Команды
# ──────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "⚡ *TezWeb.uz — Антиспам Бот*\n\n"
        "Защищаю группу от спама 24/7.\n\n"
        "*Команды для администраторов:*\n"
        "`/addword слово` — добавить слово в чёрный список\n"
        "`/delword слово` — убрать слово из списка\n"
        "`/listwords` — показать все запрещённые слова\n"
        "`/clearwords` — очистить весь список\n"
        "`/settings` — текущие настройки блокировок\n"
        "`/toggle links` — вкл/выкл блокировку ссылок\n"
        "`/toggle photos` — вкл/выкл блокировку фото\n"
        "`/toggle videos` — вкл/выкл блокировку видео\n"
        "`/info` — о создателе бота"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "⚡ *TezWeb.uz*\n"
        "_Сайты, которые загружаются быстрее и приносят заказы_\n\n"
        "Делаем сайты за 1 секунду для онлайн-магазинов, "
        "кафе, доставки и любого бизнеса. Чистый код, "
        "SEO 100/100 и интеграция с Telegram.\n\n"
        "📌 *Что мы делаем:*\n"
        "• Сайты на чистом коде — от 8 000 000 сум\n"
        "• Telegram боты с ИИ — от 6 000 000 сум\n"
        "• Яндекс Директ и Google Ads\n"
        "• SEO продвижение\n\n"
        "✅ Первые заявки за 3 дня\n"
        "✅ Ответим за 15 минут\n"
        "✅ Результат или возврат средств"
    )
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🌐 Сайт", url="https://tezweb.uz/")],
        [InlineKeyboardButton("💬 Написать в Telegram", url="https://t.me/Shohdollar22")],
    ])
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=keyboard)


async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await is_admin(update, context):
        await update.message.reply_text("❌ Только администраторы могут это делать.")
        return

    on  = "✅ Вкл"
    off = "❌ Выкл"
    text = (
        "⚙️ *Текущие настройки бота:*\n\n"
        f"🔗 Блокировка ссылок: {on if SETTINGS['block_links']  else off}\n"
        f"📷 Блокировка фото:   {on if SETTINGS['block_photos'] else off}\n"
        f"🎥 Блокировка видео:  {on if SETTINGS['block_videos'] else off}\n\n"
        "Переключить: `/toggle links` / `/toggle photos` / `/toggle videos`"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await is_admin(update, context):
        await update.message.reply_text("❌ Только администраторы могут это делать.")
        return

    if not context.args:
        await update.message.reply_text(
            "Использование: `/toggle links` / `/toggle photos` / `/toggle videos`",
            parse_mode="Markdown"
        )
        return

    arg = context.args[0].lower()
    mapping = {
        "links":  "block_links",
        "photos": "block_photos",
        "videos": "block_videos",
    }

    if arg not in mapping:
        await update.message.reply_text("❌ Неизвестный параметр. Используй: `links`, `photos`, `videos`", parse_mode="Markdown")
        return

    key = mapping[arg]
    SETTINGS[key] = not SETTINGS[key]
    save_settings(SETTINGS)

    status = "✅ включена" if SETTINGS[key] else "❌ выключена"
    labels = {"links": "Блокировка ссылок", "photos": "Блокировка фото", "videos": "Блокировка видео"}
    await update.message.reply_text(f"{labels[arg]}: {status}")


async def cmd_addword(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await is_admin(update, context):
        await update.message.reply_text("❌ Только администраторы могут это делать.")
        return
    if not context.args:
        await update.message.reply_text("Использование: `/addword слово`", parse_mode="Markdown")
        return

    word = " ".join(context.args).strip().lower()
    if word in KEYWORDS:
        await update.message.reply_text(f'Слово *"{word}"* уже в списке.', parse_mode="Markdown")
        return

    KEYWORDS.add(word)
    save_keywords(KEYWORDS)
    await update.message.reply_text(f'✅ Добавлено: *"{word}"*', parse_mode="Markdown")


async def cmd_delword(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await is_admin(update, context):
        await update.message.reply_text("❌ Только администраторы могут это делать.")
        return
    if not context.args:
        await update.message.reply_text("Использование: `/delword слово`", parse_mode="Markdown")
        return

    word = " ".join(context.args).strip().lower()
    if word not in KEYWORDS:
        await update.message.reply_text(f'Слово *"{word}"* не найдено.', parse_mode="Markdown")
        return

    KEYWORDS.discard(word)
    save_keywords(KEYWORDS)
    await update.message.reply_text(f'🗑 Удалено: *"{word}"*', parse_mode="Markdown")


async def cmd_listwords(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await is_admin(update, context):
        await update.message.reply_text("❌ Только администраторы могут это делать.")
        return
    if not KEYWORDS:
        await update.message.reply_text("📋 Список запрещённых слов пуст.")
        return

    words = sorted(KEYWORDS)
    lines = "\n".join(f"  • {w}" for w in words)
    await update.message.reply_text(
        f"📋 *Запрещённые слова ({len(words)}):**\n{lines}",
        parse_mode="Markdown",
    )


async def cmd_clearwords(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await is_admin(update, context):
        await update.message.reply_text("❌ Только администраторы могут это делать.")
        return
    KEYWORDS.clear()
    save_keywords(KEYWORDS)
    await update.message.reply_text("🧹 Список запрещённых слов очищен.")


# ──────────────────────────────────────────────
# Обработчики сообщений
# ──────────────────────────────────────────────

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Проверяет текстовые сообщения на спам-слова и ссылки."""
    message = update.message
    if not message or not message.text:
        return
    if update.effective_chat.type == "private":
        return
    if await is_admin(update, context):
        return

    text = message.text

    # Проверка ключевых слов
    found_word = contains_spam_word(text)
    if found_word:
        await delete_and_kick(update, context, f"Taqiqlangan so'z: \"{found_word}\"")
        return

    # Проверка ссылок
    if SETTINGS["block_links"] and contains_link(text):
        await delete_and_kick(update, context, "Xabar ichida havola (link) bor")
        return


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Удаляет фото от не-админов если блокировка включена."""
    if not SETTINGS["block_photos"]:
        return
    if update.effective_chat.type == "private":
        return
    if await is_admin(update, context):
        return

    await delete_and_kick(update, context, "Guruhda rasm yuborish taqiqlangan")


async def handle_video(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Удаляет видео от не-админов если блокировка включена."""
    if not SETTINGS["block_videos"]:
        return
    if update.effective_chat.type == "private":
        return
    if await is_admin(update, context):
        return

    await delete_and_kick(update, context, "Guruhda video yuborish taqiqlangan")


# ──────────────────────────────────────────────
# Запуск
# ──────────────────────────────────────────────

def main() -> None:
    if BOT_TOKEN == "ВАШ_ТОКЕН_ЗДЕСЬ":
        print("❌ Вставь токен бота через Railway Variables: BOT_TOKEN=твой_токен")
        return

    app = Application.builder().token(BOT_TOKEN).build()

    # Команды
    app.add_handler(CommandHandler("start",      cmd_start))
    app.add_handler(CommandHandler("info",       cmd_info))
    app.add_handler(CommandHandler("settings",   cmd_settings))
    app.add_handler(CommandHandler("toggle",     cmd_toggle))
    app.add_handler(CommandHandler("addword",    cmd_addword))
    app.add_handler(CommandHandler("delword",    cmd_delword))
    app.add_handler(CommandHandler("listwords",  cmd_listwords))
    app.add_handler(CommandHandler("clearwords", cmd_clearwords))

    # Обработчики контента
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(MessageHandler(filters.PHOTO,                   handle_photo))
    app.add_handler(MessageHandler(filters.VIDEO | filters.VIDEO_NOTE, handle_video))

    logger.info("✅ TezWeb Антиспам Бот запущен!")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
