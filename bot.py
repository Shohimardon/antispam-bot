"""
Telegram Antispam Bot — TezWeb.uz
Barcha funksiyalar: antispam, antiflood, kapcha, whitelist, statistika, hisobotlar
"""

import json
import logging
import os
import re
import asyncio
import unicodedata
import datetime as dt
from pathlib import Path
from collections import defaultdict

from telegram import Update, ChatMember, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ChatMemberHandler,
    ContextTypes,
    filters,
)

# ──────────────────────────────────────────────
# Sozlamalar
# ──────────────────────────────────────────────

BOT_TOKEN  = os.environ.get("BOT_TOKEN", "")
DATA_DIR   = Path(os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", "/data"))

KEYWORDS_FILE  = str(DATA_DIR / "keywords.json")
SETTINGS_FILE  = str(DATA_DIR / "settings.json")
GROUPS_FILE    = str(DATA_DIR / "groups.json")
STATS_FILE     = str(DATA_DIR / "stats.json")
WHITELIST_FILE = str(DATA_DIR / "whitelist.json")
SLOWMODE_FILE  = str(DATA_DIR / "slowmode.json")

ADMIN_IDS = {6038976942, 2018064843}

logging.basicConfig(format="%(asctime)s | %(levelname)s | %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

URL_REGEX     = re.compile(r'(https?://\S+|www\.\S+|t\.me/\S+)', re.IGNORECASE)
MENTION_REGEX = re.compile(r'@[a-zA-Z0-9_]{4,}')

# Antiflood: {chat_id: {user_id: [timestamps]}}
flood_tracker = defaultdict(lambda: defaultdict(list))

# Slowmode: {chat_id: {user_id: last_message_time}}
slowmode_tracker = defaultdict(dict)

# Kapcha: {chat_id: {user_id: {"answer": int, "msg_id": int}}}
captcha_pending = defaultdict(dict)

# ──────────────────────────────────────────────
# Matn tozalash
# ──────────────────────────────────────────────

def clean_text(text: str) -> str:
    invisible = ['\u200b','\u200c','\u200d','\u200e','\u200f',
                 '\ufe0f','\u2060','\ufeff','\u00ad','\u034f']
    for char in invisible:
        text = text.replace(char, '')
    return unicodedata.normalize('NFKC', text).lower()

# ──────────────────────────────────────────────
# Saqlash funksiyalari
# ──────────────────────────────────────────────

def load_json(path, default):
    try:
        if Path(path).exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_keywords() -> set:
    return set(load_json(KEYWORDS_FILE, []))

def save_keywords(kw: set):
    save_json(KEYWORDS_FILE, list(kw))

def load_settings() -> dict:
    defaults = {
        "block_links": True, "block_photos": True,
        "block_videos": True, "antiflood": True,
        "captcha": False, "slowmode": False,
        "block_arabic": False, "slowmode_seconds": 60,
        "flood_limit": 5, "flood_seconds": 10,
    }
    saved = load_json(SETTINGS_FILE, {})
    defaults.update(saved)
    return defaults

def save_settings(s: dict):
    save_json(SETTINGS_FILE, s)

def load_groups() -> set:
    return set(load_json(GROUPS_FILE, []))

def save_groups(g: set):
    save_json(GROUPS_FILE, list(g))

def load_stats() -> dict:
    return load_json(STATS_FILE, {"total": 0, "today": 0, "week": 0, "last_reset": "", "last_week_reset": "", "groups": {}})

def save_stats(s: dict):
    save_json(STATS_FILE, s)

def load_whitelist() -> set:
    return set(load_json(WHITELIST_FILE, []))

def save_whitelist(w: set):
    save_json(WHITELIST_FILE, list(w))

KEYWORDS  = load_keywords()
SETTINGS  = load_settings()
GROUPS    = load_groups()
WHITELIST = load_whitelist()

# ──────────────────────────────────────────────
# Statistika
# ──────────────────────────────────────────────

def add_kick_stat(chat_id: int):
    stats = load_stats()
    today = dt.date.today().isoformat()
    week  = dt.date.today().isocalendar()[1]

    if stats.get("last_reset") != today:
        stats["today"] = 0
        stats["last_reset"] = today

    if stats.get("last_week_reset") != str(week):
        stats["week"] = 0
        stats["last_week_reset"] = str(week)

    stats["total"] = stats.get("total", 0) + 1
    stats["today"] = stats.get("today", 0) + 1
    stats["week"]  = stats.get("week", 0) + 1

    chat_key = str(chat_id)
    if chat_key not in stats["groups"]:
        stats["groups"][chat_key] = 0
    stats["groups"][chat_key] += 1

    save_stats(stats)

# ──────────────────────────────────────────────
# Yordamchi
# ──────────────────────────────────────────────

def is_super_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

async def is_admin_in_chat(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
        return member.status in (ChatMember.ADMINISTRATOR, ChatMember.OWNER)
    except Exception:
        return False

def contains_keyword(text: str) -> bool:
    if not KEYWORDS:
        return False
    t = clean_text(text)
    return any(kw in t for kw in KEYWORDS)

def is_arabic_or_chinese(text: str) -> bool:
    for char in text:
        cp = ord(char)
        if (0x0600 <= cp <= 0x06FF or   # Arabic
            0x4E00 <= cp <= 0x9FFF or   # Chinese
            0x3040 <= cp <= 0x30FF):    # Japanese
            return True
    return False

# ──────────────────────────────────────────────
# Kik va o'chirish
# ──────────────────────────────────────────────

async def delete_and_kick(update: Update, context: ContextTypes.DEFAULT_TYPE, reason: str):
    chat = update.effective_chat
    user = update.effective_user
    if not user:
        return

    name = f"@{user.username}" if user.username else user.first_name

    try:
        await update.message.delete()
    except Exception:
        pass

    try:
        await context.bot.ban_chat_member(chat.id, user.id)
        await context.bot.unban_chat_member(chat.id, user.id)
    except Exception:
        pass

    add_kick_stat(chat.id)

    bot_username = context.bot.username
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Guruhga qo'shish", url=f"https://t.me/{bot_username}?startgroup=true")],
        [InlineKeyboardButton("📢 @tezweb_uz", url="https://t.me/tezweb_uz")],
    ])

    notice = await context.bot.send_message(
        chat_id=chat.id,
        text=(
            f"🚫 *{name}*, siz guruh qoidalarini buzgansiz!\n"
            f"📌 Sabab: {reason}\n"
            f"👢 Siz guruhdan chiqarib yuborldingiz.\n\n"
            f"🛡 Guruhingizda spam ko'pmi? Meni qo'shing — "
            f"spamdan 24/7 himoya qilaman!"
        ),
        parse_mode="Markdown",
        reply_markup=keyboard
    )

    async def delete_notice():
        await asyncio.sleep(100)
        try:
            await notice.delete()
        except Exception:
            pass

    asyncio.create_task(delete_notice())
    logger.info("Kicked: %s | %s | %s", name, chat.title, reason)

# ──────────────────────────────────────────────
# Antiflood tekshirish
# ──────────────────────────────────────────────

def check_flood(chat_id: int, user_id: int) -> bool:
    import time
    now = time.time()
    limit   = SETTINGS.get("flood_limit", 5)
    seconds = SETTINGS.get("flood_seconds", 10)

    msgs = flood_tracker[chat_id][user_id]
    msgs = [t for t in msgs if now - t < seconds]
    msgs.append(now)
    flood_tracker[chat_id][user_id] = msgs
    return len(msgs) >= limit

# ──────────────────────────────────────────────
# Slowmode tekshirish
# ──────────────────────────────────────────────

def check_slowmode(chat_id: int, user_id: int) -> bool:
    import time
    now     = time.time()
    seconds = SETTINGS.get("slowmode_seconds", 60)
    last    = slowmode_tracker[chat_id].get(user_id, 0)
    if now - last < seconds:
        return True
    slowmode_tracker[chat_id][user_id] = now
    return False

# ──────────────────────────────────────────────
# Kapcha
# ──────────────────────────────────────────────

async def send_captcha(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, name: str):
    import random
    a, b   = random.randint(1, 9), random.randint(1, 9)
    answer = a + b
    wrong1 = answer + random.choice([-2, -1, 1, 2])
    wrong2 = answer + random.choice([-3, 3, -4, 4])

    buttons = [a + b, wrong1, wrong2]
    random.shuffle(buttons)

    keyboard = InlineKeyboardMarkup([[
        InlineKeyboardButton(str(b), callback_data=f"cap_{user_id}_{b}")
        for b in buttons
    ]])

    msg = await context.bot.send_message(
        chat_id=chat_id,
        text=f"👋 Xush kelibsiz, {name}!\n\n"
             f"🤖 Siz bot emasligingizni isbotlang:\n"
             f"*{a} + {b} = ?*\n\n"
             f"⏰ 60 soniya ichida javob bering!",
        parse_mode="Markdown",
        reply_markup=keyboard
    )

    captcha_pending[chat_id][user_id] = {"answer": answer, "msg_id": msg.message_id}

    async def captcha_timeout():
        await asyncio.sleep(60)
        if user_id in captcha_pending.get(chat_id, {}):
            try:
                await context.bot.ban_chat_member(chat_id, user_id)
                await context.bot.unban_chat_member(chat_id, user_id)
                await msg.delete()
                del captcha_pending[chat_id][user_id]
            except Exception:
                pass

    asyncio.create_task(captcha_timeout())

# ──────────────────────────────────────────────
# Yangi a'zo
# ──────────────────────────────────────────────

async def handle_new_member(update: Update, context: ContextTypes.DEFAULT_TYPE):
    for member in (update.message.new_chat_members or []):
        if member.is_bot:
            continue
        name    = f"@{member.username}" if member.username else member.first_name
        chat_id = update.effective_chat.id

        if SETTINGS.get("captcha"):
            await send_captcha(update, context, member.id, chat_id, name)
        else:
            text = (
                f"👋 Xush kelibsiz, {name}!\n\n"
                f"Bu *TezWeb.uz* rasmiy muhokama guruhimiz.\n\n"
                f"❓ Savol berish uchun xabar oxiriga *?* qo'ying\n"
                f"yoki botning xabariga reply qiling.\n\n"
                f"📢 Kanal: @tezweb_uz\n"
                f"🌐 tezweb.uz | 📩 @Shohdollar22"
            )
            await context.bot.send_message(chat_id, text, parse_mode="Markdown")

# ──────────────────────────────────────────────
# Kapcha callback
# ──────────────────────────────────────────────

async def handle_captcha_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not query or not query.data.startswith("cap_"):
        return

    parts   = query.data.split("_")
    user_id = int(parts[1])
    answer  = int(parts[2])
    chat_id = query.message.chat.id

    if query.from_user.id != user_id:
        await query.answer("Bu sizning kapchangiz emas!", show_alert=True)
        return

    pending = captcha_pending.get(chat_id, {}).get(user_id)
    if not pending:
        await query.answer("Kapcha muddati tugagan.")
        return

    if answer == pending["answer"]:
        await query.answer("✅ To'g'ri! Guruhga xush kelibsiz!")
        try:
            await query.message.delete()
        except Exception:
            pass
        del captcha_pending[chat_id][user_id]
    else:
        await query.answer("❌ Noto'g'ri! Siz bot sifatida aniqlangiz.")
        try:
            await context.bot.ban_chat_member(chat_id, user_id)
            await context.bot.unban_chat_member(chat_id, user_id)
            await query.message.delete()
        except Exception:
            pass
        if user_id in captcha_pending.get(chat_id, {}):
            del captcha_pending[chat_id][user_id]

# ──────────────────────────────────────────────
# Xabarlarni tekshirish
# ──────────────────────────────────────────────

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    if update.effective_chat.type == "private":
        return
    if update.effective_message and update.effective_message.sender_chat:
        return

    user    = update.effective_user
    chat_id = update.effective_chat.id
    text    = update.message.text

    if not user:
        return
    if user.id in WHITELIST:
        logger.info("Whitelist: %s", user.id)
        return
    if await is_admin_in_chat(update, context):
        logger.info("Admin, skip: %s", user.id)
        return

    logger.info("Checking: %s | text: %s", user.id, text[:30])

    # Antiflood
    if SETTINGS.get("antiflood") and check_flood(chat_id, user.id):
        await delete_and_kick(update, context, "Flood (juda ko'p xabar)")
        return

    # Slowmode
    if SETTINGS.get("slowmode") and check_slowmode(chat_id, user.id):
        try:
            await update.message.delete()
        except Exception:
            pass
        return

    # Arabic/Chinese bloklash
    if SETTINGS.get("block_arabic") and is_arabic_or_chinese(text):
        await delete_and_kick(update, context, "Taqiqlangan til (arab/xitoy)")
        return

    # Havolalar
    if SETTINGS.get("block_links"):
        if URL_REGEX.search(text) or MENTION_REGEX.search(text):
            await delete_and_kick(update, context, "Xabar ichida havola (link) bor")
            return

    # Kalit sozlar
    if contains_keyword(text):
        await delete_and_kick(update, context, "Taqiqlangan so'z aniqlandi")
        return


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not SETTINGS.get("block_photos"):
        return
    if update.effective_chat.type == "private":
        return
    if update.effective_message and update.effective_message.sender_chat:
        return
    if update.effective_user and update.effective_user.id in WHITELIST:
        return
    if await is_admin_in_chat(update, context):
        return
    await delete_and_kick(update, context, "Guruhda rasm yuborish taqiqlangan")


async def handle_video(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not SETTINGS.get("block_videos"):
        return
    if update.effective_chat.type == "private":
        return
    if update.effective_message and update.effective_message.sender_chat:
        return
    if update.effective_user and update.effective_user.id in WHITELIST:
        return
    if await is_admin_in_chat(update, context):
        return
    await delete_and_kick(update, context, "Guruhda video yuborish taqiqlangan")

# ──────────────────────────────────────────────
# Komandalar
# ──────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    bot_username = context.bot.username

    if update.effective_chat.type in ("group", "supergroup"):
        text = (
            "🛡 *TezWeb Antispam Bot* — bu yerda!\n\n"
            "Men guruhingizni spam, havolalar, rasm va videodan "
            "*24/7 himoya qilaman!*\n\n"
            "✅ Spamchilarni avtomatik o'chiraman\n"
            "✅ Antiflood himoyasi\n"
            "✅ Kapcha tizimi\n"
            "✅ Taqiqlangan so'zlar filtri\n\n"
            "👥 Boshqa guruhlaringizga ham qo'shing:"
        )
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("➕ Guruhga qo'shish", url=f"https://t.me/{bot_username}?startgroup=true")],
            [InlineKeyboardButton("📢 @tezweb_uz", url="https://t.me/tezweb_uz")],
        ])
        await update.message.reply_text(text, parse_mode="Markdown", reply_markup=keyboard)
        return

    if is_super_admin(update.effective_user.id):
        text = (
            "⚡ *TezWeb.uz — Antispam Bot*\n\n"
            "Salom, admin! Buyruqlar:\n\n"
            "*Sozlamalar:*\n"
            "`/settings` — hozirgi sozlamalar\n"
            "`/toggle links` — havolalar\n"
            "`/toggle photos` — rasmlar\n"
            "`/toggle videos` — videolar\n"
            "`/toggle antiflood` — antiflood\n"
            "`/toggle captcha` — kapcha\n"
            "`/toggle slowmode` — sekin rejim\n"
            "`/toggle arabic` — arab/xitoy bloklash\n\n"
            "*So'zlar:*\n"
            "`/addword so'z` — qora ro'yxatga qo'shish\n"
            "`/delword so'z` — o'chirish\n"
            "`/listwords` — ro'yxat\n"
            "`/clearwords` — tozalash\n\n"
            "*Whitelist:*\n"
            "`/whitelist add ID` — qo'shish\n"
            "`/whitelist remove ID` — o'chirish\n"
            "`/whitelist list` — ko'rish\n\n"
            "*Guruhlar:*\n"
            "`/addgroup` — guruh qo'shish (guruhda)\n"
            "`/removegroup` — o'chirish\n"
            "`/listgroups` — ko'rish\n\n"
            "*Statistika:*\n"
            "`/stats` — statistika\n"
        )
    else:
        text = (
            "🛡 *TezWeb Antispam Bot*\n\n"
            "Guruhingizni spamdan himoya qilaman!\n\n"
            "📩 Batafsil: @Shohdollar22"
        )

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Guruhga qo'shish", url=f"https://t.me/{bot_username}?startgroup=true")],
        [InlineKeyboardButton("📢 @tezweb_uz", url="https://t.me/tezweb_uz")],
        [InlineKeyboardButton("💬 @Shohdollar22", url="https://t.me/Shohdollar22")],
    ])
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=keyboard)


async def cmd_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    bot_username = context.bot.username
    text = (
        "🛡 *TezWeb Antispam Bot — Barcha funksiyalar:*\n\n"
        "*🔒 Himoya:*\n"
        "• Havola va @username bloklash\n"
        "• Rasm yuborishni bloklash\n"
        "• Video yuborishni bloklash\n"
        "• Taqiqlangan so'zlar filtri\n"
        "• Antiflood (5+ xabar/10 sek → kik)\n"
        "• Kapcha yangi a'zolar uchun\n"
        "• Sekin rejim (1 xabar/daqiqa)\n"
        "• Arab/xitoy tili bloklash\n\n"
        "*📊 Statistika:*\n"
        "• Kunlik/haftalik/umumiy hisobot\n"
        "• Har kuni 22:00 da avtomatik hisobot\n"
        "• Har yakshanba 23:00 da haftalik hisobot\n\n"
        "*⚙️ Boshqaruv:*\n"
        "• Whitelist — ishonchli foydalanuvchilar\n"
        "• Har bir funksiyani yoqish/o'chirish\n"
        "• Guruhlar ro'yxati boshqaruvi\n\n"
        "*📢 Reklama:*\n"
        "• Har kik uchun avtomatik reklama\n"
        "• 7:00 va 21:00 da reklama xabari\n\n"
        f"👥 Guruhga qo'shish: @{bot_username}\n"
        "📩 Sozlash: @Shohdollar22"
    )
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Guruhga qo'shish", url=f"https://t.me/{bot_username}?startgroup=true")],
        [InlineKeyboardButton("📢 @tezweb_uz", url="https://t.me/tezweb_uz")],
    ])
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=keyboard)


async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    s = SETTINGS
    on  = "✅"
    off = "❌"
    text = (
        f"⚙️ *Hozirgi sozlamalar:*\n\n"
        f"{on if s['block_links']  else off} Havolalar bloklash\n"
        f"{on if s['block_photos'] else off} Rasmlar bloklash\n"
        f"{on if s['block_videos'] else off} Videolar bloklash\n"
        f"{on if s.get('antiflood', True) else off} Antiflood\n"
        f"{on if s.get('captcha', False)  else off} Kapcha\n"
        f"{on if s.get('slowmode', False) else off} Sekin rejim ({s.get('slowmode_seconds', 60)} sek)\n"
        f"{on if s.get('block_arabic', False) else off} Arab/xitoy bloklash\n\n"
        f"*O'zgartirish:* `/toggle links/photos/videos/antiflood/captcha/slowmode/arabic`"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Ishlatish: /toggle links|photos|videos|antiflood|captcha|slowmode|arabic")
        return

    key_map = {
        "links": "block_links", "photos": "block_photos",
        "videos": "block_videos", "antiflood": "antiflood",
        "captcha": "captcha", "slowmode": "slowmode",
        "arabic": "block_arabic",
    }
    arg = context.args[0].lower()
    key = key_map.get(arg)
    if not key:
        await update.message.reply_text("Noma'lum parametr!")
        return

    SETTINGS[key] = not SETTINGS.get(key, True)
    save_settings(SETTINGS)
    status = "✅ Yoqildi" if SETTINGS[key] else "❌ O'chirildi"
    await update.message.reply_text(f"{status}: *{arg}*", parse_mode="Markdown")


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_super_admin(update.effective_user.id):
        return
    stats = load_stats()
    text = (
        f"📊 *Statistika:*\n\n"
        f"📅 Bugun: *{stats.get('today', 0)}* ta kik\n"
        f"📆 Bu hafta: *{stats.get('week', 0)}* ta kik\n"
        f"📈 Jami: *{stats.get('total', 0)}* ta kik\n\n"
        f"🏆 *Eng faol guruhlar:*\n"
    )
    groups = stats.get("groups", {})
    sorted_groups = sorted(groups.items(), key=lambda x: x[1], reverse=True)[:5]
    for i, (gid, count) in enumerate(sorted_groups, 1):
        text += f"{i}. `{gid}` — {count} ta\n"
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_addword(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Ishlatish: /addword so'z")
        return
    word = " ".join(context.args).lower().strip()
    KEYWORDS.add(word)
    save_keywords(KEYWORDS)
    await update.message.reply_text(f'✅ Qoshildi: "{word}"\nEndi bu soz bilan yangi xabarlar avtomatik ochiriladi.')


async def cmd_delword(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Ishlatish: /delword so'z")
        return
    word = " ".join(context.args).lower().strip()
    KEYWORDS.discard(word)
    save_keywords(KEYWORDS)
    await update.message.reply_text(f'Ochirildi: "{word}"')


async def cmd_listwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    if not KEYWORDS:
        await update.message.reply_text("Taqiqlangan sozlar royxati bosh.\n\nQoshish uchun: /addword soz")
        return
    words = sorted(KEYWORDS)
    lines = "\n".join(f"  • {w}" for w in words)
    await update.message.reply_text(f"Taqiqlangan sozlar ({len(words)}):\n\n{lines}")


async def cmd_clearwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    KEYWORDS.clear()
    save_keywords(KEYWORDS)
    await update.message.reply_text("Royxat tozalandi.")


async def cmd_whitelist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Ishlatish: /whitelist add ID | /whitelist remove ID | /whitelist list")
        return

    action = context.args[0].lower()
    if action == "list":
        if not WHITELIST:
            await update.message.reply_text("Whitelist bosh.")
        else:
            await update.message.reply_text("Whitelist:\n" + "\n".join(f"• {uid}" for uid in WHITELIST))
        return

    if len(context.args) < 2:
        await update.message.reply_text("ID kiriting!")
        return

    try:
        uid = int(context.args[1])
    except ValueError:
        await update.message.reply_text("Noto'g'ri ID!")
        return

    if action == "add":
        WHITELIST.add(uid)
        save_whitelist(WHITELIST)
        await update.message.reply_text(f"✅ {uid} whitelistga qoshildi.")
    elif action == "remove":
        WHITELIST.discard(uid)
        save_whitelist(WHITELIST)
        await update.message.reply_text(f"Ochirildi: {uid}")


async def cmd_addgroup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type == "private":
        await update.message.reply_text("Bu buyruqni guruhda yuboring.")
        return
    if not is_super_admin(update.effective_user.id):
        return
    chat_id    = update.effective_chat.id
    chat_title = update.effective_chat.title or str(chat_id)
    GROUPS.add(chat_id)
    save_groups(GROUPS)
    await update.message.reply_text(f"✅ *{chat_title}* reklama royxatiga qoshildi!", parse_mode="Markdown")


async def cmd_removegroup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type == "private":
        await update.message.reply_text("Bu buyruqni guruhda yuboring.")
        return
    if not is_super_admin(update.effective_user.id):
        return
    chat_id    = update.effective_chat.id
    chat_title = update.effective_chat.title or str(chat_id)
    GROUPS.discard(chat_id)
    save_groups(GROUPS)
    await update.message.reply_text(f"Ochirildi: *{chat_title}*", parse_mode="Markdown")


async def cmd_listgroups(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    if not GROUPS:
        await update.message.reply_text("Reklama guruhlari royxati bosh.\n\nQoshish: guruhga boring va /addgroup yuboring.")
        return
    await update.message.reply_text(f"Reklama guruhlari: {len(GROUPS)} ta\n\n" + "\n".join(f"• {g}" for g in GROUPS))


# ──────────────────────────────────────────────
# Reklama va hisobotlar
# ──────────────────────────────────────────────

async def send_promo(bot):
    if not GROUPS:
        return
    bot_username = bot.username
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Guruhga qo'shish", url=f"https://t.me/{bot_username}?startgroup=true")],
        [InlineKeyboardButton("📢 @tezweb_uz", url="https://t.me/tezweb_uz")],
    ])
    text = (
        "🛡 *Guruhingizda spam ko'p bo'lsa* — meni qo'shing!\n\n"
        "✅ Spamchilarni avtomatik o'chiraman\n"
        "✅ Havolalar va reklamani bloklash\n"
        "✅ 24/7 ishlayman\n\n"
        "👇 Qo'shish uchun tugmani bosing:"
    )
    for chat_id in list(GROUPS):
        try:
            await bot.send_message(chat_id=chat_id, text=text, parse_mode="Markdown", reply_markup=keyboard)
        except Exception as e:
            logger.error("Promo xato %s: %s", chat_id, e)


async def send_daily_report(bot):
    """Har kuni 22:00 da kunlik hisobot."""
    stats = load_stats()
    text = (
        f"📊 *Kunlik hisobot — {dt.date.today().isoformat()}*\n\n"
        f"🦠 Bugun kiklangan: *{stats.get('today', 0)}* ta spam\n"
        f"📈 Jami barcha vaqt: *{stats.get('total', 0)}* ta\n\n"
        f"tezweb.uz | @tezweb_uz"
    )
    for admin_id in ADMIN_IDS:
        try:
            await bot.send_message(chat_id=admin_id, text=text, parse_mode="Markdown")
        except Exception:
            pass


async def send_weekly_report(bot):
    """Har yakshanba 23:00 da haftalik hisobot."""
    stats = load_stats()
    groups = stats.get("groups", {})
    sorted_groups = sorted(groups.items(), key=lambda x: x[1], reverse=True)[:5]

    top_text = ""
    for i, (gid, count) in enumerate(sorted_groups, 1):
        top_text += f"{i}. `{gid}` — {count} ta\n"

    text = (
        f"📆 *Haftalik hisobot*\n\n"
        f"🦠 Bu hafta: *{stats.get('week', 0)}* ta spam\n"
        f"📈 Jami: *{stats.get('total', 0)}* ta\n\n"
        f"🏆 *Top guruhlar:*\n{top_text}\n"
        f"tezweb.uz | @tezweb_uz"
    )
    for admin_id in ADMIN_IDS:
        try:
            await bot.send_message(chat_id=admin_id, text=text, parse_mode="Markdown")
        except Exception:
            pass


# ──────────────────────────────────────────────
# Ishga tushirish
# ──────────────────────────────────────────────

def main() -> None:
    if not BOT_TOKEN:
        print("BOT_TOKEN ni Railway Variables ga kiriting")
        return

    app = Application.builder().token(BOT_TOKEN).build()

    # Komandalar
    app.add_handler(CommandHandler("start",      cmd_start))
    app.add_handler(CommandHandler("info",       cmd_info))
    app.add_handler(CommandHandler("settings",   cmd_settings))
    app.add_handler(CommandHandler("toggle",     cmd_toggle))
    app.add_handler(CommandHandler("stats",      cmd_stats))
    app.add_handler(CommandHandler("addword",    cmd_addword))
    app.add_handler(CommandHandler("delword",    cmd_delword))
    app.add_handler(CommandHandler("listwords",  cmd_listwords))
    app.add_handler(CommandHandler("clearwords", cmd_clearwords))
    app.add_handler(CommandHandler("whitelist",  cmd_whitelist))
    app.add_handler(CommandHandler("addgroup",   cmd_addgroup))
    app.add_handler(CommandHandler("removegroup",cmd_removegroup))
    app.add_handler(CommandHandler("listgroups", cmd_listgroups))

    # Xabarlar
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, handle_new_member))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(MessageHandler(filters.VIDEO | filters.VIDEO_NOTE, handle_video))

    # Callback (kapcha)
    from telegram.ext import CallbackQueryHandler
    app.add_handler(CallbackQueryHandler(handle_captcha_callback, pattern=r"^cap_"))

    # Jadval
    jq = app.job_queue
    jq.run_daily(lambda ctx: asyncio.create_task(send_promo(ctx.bot)),
                 time=dt.time(2, 0, 0))    # 7:00 Toshkent
    jq.run_daily(lambda ctx: asyncio.create_task(send_promo(ctx.bot)),
                 time=dt.time(16, 0, 0))   # 21:00 Toshkent
    jq.run_daily(lambda ctx: asyncio.create_task(send_daily_report(ctx.bot)),
                 time=dt.time(17, 0, 0))   # 22:00 Toshkent
    jq.run_daily(lambda ctx: asyncio.create_task(send_weekly_report(ctx.bot)),
                 time=dt.time(18, 0, 0),   # 23:00 Toshkent
                 days=(6,))                # 6 = Yakshanba

    logger.info("✅ TezWeb Antispam Bot ishga tushdi!")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
