"""
Telegram Antispam Bot — TezWeb.uz
==================================
Funksiyalar:
  - Taqiqlangan so'zli xabarlarni o'chiradi
  - Havolalarni (http/https, t.me, @username) o'chiradi
  - Admin bo'lmaganlarning rasm va videolarini o'chiradi
  - Qoidabuzarni guruhdan chiqarib yuboradi
  - Faqat guruh adminlari so'zlarni boshqara oladi (shaxsiy xabarda)
"""

import json
import logging
import os
import re
import asyncio
from pathlib import Path

from telegram import Update, ChatMember, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# ──────────────────────────────────────────────
# Sozlamalar
# ──────────────────────────────────────────────

BOT_TOKEN     = os.environ.get("BOT_TOKEN", "")
KEYWORDS_FILE = "keywords.json"
SETTINGS_FILE = "settings.json"
# Guruh ID — bot qaysi guruhni himoya qilishini biladi
# Bo'sh qoldirsang barcha guruhlarda ishlaydi
ALLOWED_GROUP_ID = int(os.environ.get("GROUP_ID", "0"))

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

URL_REGEX     = re.compile(r'(https?://\S+|www\.\S+|t\.me/\S+)', re.IGNORECASE)
MENTION_REGEX = re.compile(r'@[a-zA-Z0-9_]{4,}')

# ──────────────────────────────────────────────
# Saqlash
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
# Yordamchi funksiyalar
# ──────────────────────────────────────────────

async def is_group_admin(user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Foydalanuvchi guruh admini ekanligini tekshiradi (shaxsiy xabardan)."""
    if ALLOWED_GROUP_ID == 0:
        return False
    try:
        member = await context.bot.get_chat_member(ALLOWED_GROUP_ID, user_id)
        return member.status in (ChatMember.ADMINISTRATOR, ChatMember.OWNER)
    except Exception:
        return False

async def is_admin_in_chat(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Joriy chatdagi admin ekanligini tekshiradi."""
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
    try:
        await context.bot.ban_chat_member(chat_id, user_id)
        await asyncio.sleep(1)
        await context.bot.unban_chat_member(chat_id, user_id)
        return True
    except Exception as e:
        logger.error("Foydalanuvchini chiqarib bo'lmadi %s: %s", user_id, e)
        return False

async def delete_and_kick(update: Update, context: ContextTypes.DEFAULT_TYPE, reason: str) -> None:
    message = update.message
    user    = update.effective_user
    chat    = update.effective_chat
    name    = f"@{user.username}" if user.username else user.first_name

    try:
        await message.delete()
    except Exception as e:
        logger.error("Xabarni o'chirib bo'lmadi: %s", e)

    await kick_user(context, chat.id, user.id)

    notice = await context.bot.send_message(
        chat_id=chat.id,
        text=(
            f"🚫 *{name}*, siz guruh qoidalarini buzgansiz!\n"
            f"📌 Sabab: {reason}\n"
            f"👢 Siz guruhdan chiqarib yuborldingiz."
        ),
        parse_mode="Markdown",
    )

    logger.info("Qoidabuzar %s chiqarildi | sabab: %s", name, reason)

    await asyncio.sleep(10)
    try:
        await notice.delete()
    except Exception:
        pass

# ──────────────────────────────────────────────
# Buyruqlar — SHAXSIY XABAR (faqat adminlar)
# ──────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Guruhda /start ga javob berma
    if update.effective_chat.type != "private":
        return

    user_id  = update.effective_user.id
    is_admin = await is_group_admin(user_id, context)

    if is_admin:
        text = (
            "⚡ *TezWeb.uz — Antispam Bot*\n\n"
            "Salom, admin! Guruhni boshqarish uchun buyruqlar:\n\n"
            "`/addword so'z` — so'zni qora ro'yxatga qo'shish\n"
            "`/delword so'z` — so'zni ro'yxatdan o'chirish\n"
            "`/listwords` — barcha taqiqlangan so'zlarni ko'rish\n"
            "`/clearwords` — ro'yxatni tozalash\n"
            "`/settings` — hozirgi sozlamalar\n"
            "`/toggle links` — havolalarni bloklash yoq/yoqish\n"
            "`/toggle photos` — rasmlarni bloklash yoq/yoqish\n"
            "`/toggle videos` — videolarni bloklash yoq/yoqish\n"
            "`/info` — bot yaratuvchisi haqida"
        )
    else:
        text = (
            "⚡ *TezWeb.uz — Antispam Bot*\n\n"
            "Assalomu alaykum! Men guruhlarni spam'dan himoya qiluvchi botman.\n\n"
            "📌 Ko'proq ma'lumot uchun /info buyrug'ini yuboring."
        )
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Guruhda /info ga javob berma
    if update.effective_chat.type != "private":
        return

    text = (
        "⚡ *TezWeb.uz*\n"
        "_Tezroq yuklanadigan va buyurtma keltiruvchi saytlar_\n\n"
        "Onlayn-do'konlar, kafe, yetkazib berish va har qanday biznes uchun "
        "1 soniyada yuklanadigan saytlar yaratamiz. Toza kod, "
        "SEO 100/100 va Telegram integratsiyasi.\n\n"
        "📌 *Biz nima qilamiz:*\n"
        "• Toza kodda saytlar — 8 000 000 so'mdan\n"
        "• AI Telegram botlar — 6 000 000 so'mdan\n"
        "• Yandex Direct va Google Ads\n"
        "• SEO ilgari surish\n\n"
        "✅ Birinchi buyurtmalar 3 kunda\n"
        "✅ 15 daqiqada javob beramiz\n"
        "✅ Natija yoki pul qaytarish"
    )
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🌐 Sayt", url="https://tezweb.uz/")],
        [InlineKeyboardButton("💬 Telegram'da yozish", url="https://t.me/Shohdollar22")],
    ])
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=keyboard)


async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.type != "private":
        return
    if not await is_group_admin(update.effective_user.id, context):
        await update.message.reply_text("❌ Bu buyruq faqat guruh adminlari uchun.")
        return

    yoq  = "✅ Yoqilgan"
    yoqq = "❌ O'chirilgan"
    text = (
        "⚙️ *Hozirgi bot sozlamalari:*\n\n"
        f"🔗 Havolalarni bloklash: {yoq if SETTINGS['block_links']  else yoqq}\n"
        f"📷 Rasmlarni bloklash:   {yoq if SETTINGS['block_photos'] else yoqq}\n"
        f"🎥 Videolarni bloklash:  {yoq if SETTINGS['block_videos'] else yoqq}\n\n"
        "O'zgartirish: `/toggle links` / `/toggle photos` / `/toggle videos`"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.type != "private":
        return
    if not await is_group_admin(update.effective_user.id, context):
        await update.message.reply_text("❌ Bu buyruq faqat guruh adminlari uchun.")
        return

    if not context.args:
        await update.message.reply_text(
            "Ishlatish: `/toggle links` / `/toggle photos` / `/toggle videos`",
            parse_mode="Markdown"
        )
        return

    arg     = context.args[0].lower()
    mapping = {"links": "block_links", "photos": "block_photos", "videos": "block_videos"}

    if arg not in mapping:
        await update.message.reply_text(
            "❌ Noto'g'ri parametr. Foydalaning: `links`, `photos`, `videos`",
            parse_mode="Markdown"
        )
        return

    key = mapping[arg]
    SETTINGS[key] = not SETTINGS[key]
    save_settings(SETTINGS)

    holat  = "✅ yoqildi" if SETTINGS[key] else "❌ o'chirildi"
    nomlar = {"links": "Havolalarni bloklash", "photos": "Rasmlarni bloklash", "videos": "Videolarni bloklash"}
    await update.message.reply_text(f"{nomlar[arg]}: {holat}")


async def cmd_addword(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.type != "private":
        return
    if not await is_group_admin(update.effective_user.id, context):
        await update.message.reply_text("❌ Bu buyruq faqat guruh adminlari uchun.")
        return
    if not context.args:
        await update.message.reply_text("Ishlatish: `/addword so'z`", parse_mode="Markdown")
        return

    word = " ".join(context.args).strip().lower()
    if word in KEYWORDS:
        await update.message.reply_text(f'*"{word}"* so\'zi allaqachon ro\'yxatda.', parse_mode="Markdown")
        return

    KEYWORDS.add(word)
    save_keywords(KEYWORDS)
    await update.message.reply_text(f'✅ Qo\'shildi: *"{word}"*', parse_mode="Markdown")


async def cmd_delword(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.type != "private":
        return
    if not await is_group_admin(update.effective_user.id, context):
        await update.message.reply_text("❌ Bu buyruq faqat guruh adminlari uchun.")
        return
    if not context.args:
        await update.message.reply_text("Ishlatish: `/delword so'z`", parse_mode="Markdown")
        return

    word = " ".join(context.args).strip().lower()
    if word not in KEYWORDS:
        await update.message.reply_text(f'*"{word}"* so\'zi ro\'yxatda topilmadi.', parse_mode="Markdown")
        return

    KEYWORDS.discard(word)
    save_keywords(KEYWORDS)
    await update.message.reply_text(f'🗑 O\'chirildi: *"{word}"*', parse_mode="Markdown")


async def cmd_listwords(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.type != "private":
        return
    if not await is_group_admin(update.effective_user.id, context):
        await update.message.reply_text("❌ Bu buyruq faqat guruh adminlari uchun.")
        return
    if not KEYWORDS:
        await update.message.reply_text("📋 Taqiqlangan so'zlar ro'yxati bo'sh.")
        return

    words = sorted(KEYWORDS)
    lines = "\n".join(f"  • {w}" for w in words)
    await update.message.reply_text(
        f"📋 *Taqiqlangan so'zlar ({len(words)}):**\n{lines}",
        parse_mode="Markdown",
    )


async def cmd_clearwords(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.type != "private":
        return
    if not await is_group_admin(update.effective_user.id, context):
        await update.message.reply_text("❌ Bu buyruq faqat guruh adminlari uchun.")
        return
    KEYWORDS.clear()
    save_keywords(KEYWORDS)
    await update.message.reply_text("🧹 Taqiqlangan so'zlar ro'yxati tozalandi.")


# ──────────────────────────────────────────────
# Guruhda xabarlarni tekshirish
# ──────────────────────────────────────────────

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.message
    if not message or not message.text:
        return
    if update.effective_chat.type == "private":
        return
    if await is_admin_in_chat(update, context):
        return

    text = message.text

    found_word = contains_spam_word(text)
    if found_word:
        await delete_and_kick(update, context, f"Taqiqlangan so'z: \"{found_word}\"")
        return

    if SETTINGS["block_links"] and contains_link(text):
        await delete_and_kick(update, context, "Xabar ichida havola (link) bor")
        return


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not SETTINGS["block_photos"]:
        return
    if update.effective_chat.type == "private":
        return
    if await is_admin_in_chat(update, context):
        return
    await delete_and_kick(update, context, "Guruhda rasm yuborish taqiqlangan")


async def handle_video(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not SETTINGS["block_videos"]:
        return
    if update.effective_chat.type == "private":
        return
    if await is_admin_in_chat(update, context):
        return
    await delete_and_kick(update, context, "Guruhda video yuborish taqiqlangan")


# ──────────────────────────────────────────────
# Ishga tushirish
# ──────────────────────────────────────────────

def main() -> None:
    if not BOT_TOKEN:
        print("❌ Railway Variables orqali tokenni kiriting: BOT_TOKEN=sizning_tokeningiz")
        return

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start",      cmd_start))
    app.add_handler(CommandHandler("info",       cmd_info))
    app.add_handler(CommandHandler("settings",   cmd_settings))
    app.add_handler(CommandHandler("toggle",     cmd_toggle))
    app.add_handler(CommandHandler("addword",    cmd_addword))
    app.add_handler(CommandHandler("delword",    cmd_delword))
    app.add_handler(CommandHandler("listwords",  cmd_listwords))
    app.add_handler(CommandHandler("clearwords", cmd_clearwords))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(MessageHandler(filters.PHOTO,                   handle_photo))
    app.add_handler(MessageHandler(filters.VIDEO | filters.VIDEO_NOTE, handle_video))

    logger.info("✅ TezWeb Antispam Bot ishga tushdi!")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
