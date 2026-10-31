"""
Telegram Antispam Bot — TezWeb.uz
Barcha funksiyalar: antispam, antiflood, kapcha, whitelist, statistika, hisobotlar

Xavfsizlik tuzatishlari (security-fixed):
- Markdown-injection: foydalanuvchi ismi escape qilinadi (escape_markdown)
- Kapcha endi haqiqatdan mute qiladi (restrict_chat_member), to'g'ri javobdan keyin unmute
- Edited (tahrirlangan) xabarlar ham tekshiriladi (effective_message ishlatiladi)
- Caption (rasm/video/fayl ostidagi matn) ham havola/so'zga tekshiriladi + ko'proq media turi
- JSON faylga atomar yozish (os.replace) — buzilishdan himoya
- Arab/CJK diapazonlari kengaytirildi
- captcha_pending uchun xavfsiz .pop()
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

from telegram import (
    Update, ChatMember, ChatPermissions,
    InlineKeyboardButton, InlineKeyboardMarkup,
)
from telegram.helpers import escape_markdown
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

BOT_TOKEN  = os.environ.get("BOT_TOKEN", "")
DATA_DIR   = Path(os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", "/data"))

KEYWORDS_FILE  = str(DATA_DIR / "keywords.json")
SETTINGS_FILE  = str(DATA_DIR / "settings.json")
GROUPS_FILE    = str(DATA_DIR / "groups.json")
STATS_FILE     = str(DATA_DIR / "stats.json")
WHITELIST_FILE = str(DATA_DIR / "whitelist.json")
SLOWMODE_FILE  = str(DATA_DIR / "slowmode.json")
BLACKLIST_FILE = str(DATA_DIR / "blacklist.json")

ADMIN_IDS = {6038976942, 2018064843}

logging.basicConfig(format="%(asctime)s | %(levelname)s | %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# httpx har bir so'rov URL'ini (ichida token bor!) INFO darajada log qiladi —
# uni WARNING ga ko'taramiz, shunda token logga umuman tushmaydi.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


class _RedactToken(logging.Filter):
    """Qo'shimcha himoya: token biror joyda logga tushsa ham — yashiramiz."""
    def filter(self, record):
        if not BOT_TOKEN:
            return True
        try:
            if isinstance(record.msg, str) and BOT_TOKEN in record.msg:
                record.msg = record.msg.replace(BOT_TOKEN, "***TOKEN***")
            if record.args:
                record.args = tuple(
                    a.replace(BOT_TOKEN, "***TOKEN***") if isinstance(a, str) else a
                    for a in record.args
                )
        except Exception:
            pass
        return True


for _h in logging.getLogger().handlers:
    _h.addFilter(_RedactToken())

URL_REGEX     = re.compile(r'(https?://\S+|www\.\S+|t\.me/\S+)', re.IGNORECASE)
MENTION_REGEX = re.compile(r'@[a-zA-Z0-9_]{4,}')

# ── Bot-reklama / referal-farm spam («/start 71 @q1ifr54cmjbot @fnf4c0cbot …») ──
# Begona botlarni reklama qilish: bu eng xavfli spam (reyd-chaqiriq) — darhol QORA RO'YXAT.
BOTREF_REGEX   = re.compile(r'(?:@|t\.me/)[a-z0-9_]{2,}bot\b', re.IGNORECASE)  # @...bot yoki t.me/...bot
STARTREF_REGEX = re.compile(r'(/start\s+\S|[?&]start(?:group)?=)', re.IGNORECASE)  # /start <kod> yoki ?start=


def is_bot_promo_spam(text: str) -> bool:
    """Bot-reklama / referal-farm spam aniqlash.
    • «/start <kod> @xxxbot» — referal deep-link + bot = aniq spam;
    • 2+ xil @...bot — ommaviy bot reklama.
    Oddiy bitta @bot (kod yoki boshqa botsiz) bu funksiyani ishga tushirmaydi."""
    if not text:
        return False
    bots = {m.group(0).lower() for m in BOTREF_REGEX.finditer(text)}
    if not bots:
        return False
    if STARTREF_REGEX.search(text):
        return True            # /start <kod> + @bot = referal-farm
    return len(bots) >= 2      # 2+ xil @...bot = ommaviy bot reklama

# Kapcha ruxsatlari
MUTED_PERMS = ChatPermissions(can_send_messages=False)
UNMUTED_PERMS = ChatPermissions(
    can_send_messages=True,
    can_send_polls=True,
    can_send_other_messages=True,
    can_add_web_page_previews=True,
    can_invite_users=True,
)

# APK / xavfli ilova fayllari kengaytmalari
APK_EXTS = (".apk", ".apks", ".xapk", ".aab")

# "Meni admin qiling" xabari uchun throttle: {chat_id: last_ts}
recruit_throttle: dict = {}

# Antiflood: {chat_id: {user_id: [timestamps]}}
flood_tracker = defaultdict(lambda: defaultdict(list))

# Slowmode: {chat_id: {user_id: last_message_time}}
slowmode_tracker = defaultdict(dict)

# Kapcha: {chat_id: {user_id: {"answer": int, "msg_id": int}}}
captcha_pending = defaultdict(dict)

# ── Antireyd ──
# Yangi a'zolar oqimi (reyd-detektor): {chat_id: [timestamps]}
join_tracker = defaultdict(list)
# Muzlatilgan chatlar: {chat_id: True}
locked_chats: dict = {}
# "Kik haqida" bildirishnomalar throttle (reyd paytida bot o'zi flood qilmasin): {chat_id: last_ts}
notice_throttle: dict = {}

# Chatni muzlatish/ochish uchun guruhning default ruxsatlari
LOCKED_PERMS = ChatPermissions(
    can_send_messages=False, can_send_polls=False,
    can_send_other_messages=False, can_add_web_page_previews=False,
)
OPEN_PERMS = ChatPermissions(
    can_send_messages=True, can_send_polls=True,
    can_send_other_messages=True, can_add_web_page_previews=True,
    can_invite_users=True,
)

# Background tasklar GC tomonidan o'chmasligi uchun
_bg_tasks: set = set()

def _spawn(coro):
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return task

def md(text: str) -> str:
    """Markdown (v1) uchun foydalanuvchi matnini xavfsiz qilish."""
    return escape_markdown(text or "", version=1)

# ──────────────────────────────────────────────
# Matn tozalash
# ──────────────────────────────────────────────

def clean_text(text: str) -> str:
    invisible = ['​','‌','‍','‎','‏',
                 '️','⁠','﻿','­','͏']
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
        logger.exception("load_json buzildi: %s", path)
    return default

def save_json(path, data):
    """Atomar yozish: tmp faylga yozib, keyin os.replace."""
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        logger.exception("save_json xato: %s", path)
        try:
            if Path(tmp).exists():
                os.remove(tmp)
        except Exception:
            pass

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
        # Antireyd: keskin a'zolar oqimi → chatni avtomatik muzlatish
        "antiraid": True, "raid_join_threshold": 8, "raid_join_window": 30,
        "raid_autounlock_min": 10,
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

def load_blacklist() -> set:
    # JSON kalitlari string bo'lishi mumkin — har doim int ga keltiramiz
    return {int(u) for u in load_json(BLACKLIST_FILE, [])}

def save_blacklist(b: set):
    save_json(BLACKLIST_FILE, list(b))

KEYWORDS  = load_keywords()
SETTINGS  = load_settings()
GROUPS    = load_groups()
WHITELIST = load_whitelist()
BLACKLIST = load_blacklist()   # bot-reklama spamchilar — butunlay bloklangan user id lar

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
    for kw in KEYWORDS:
        if clean_text(kw) in t:
            return True
    return False

def is_apk(msg) -> bool:
    """Xabarda APK/xavfli ilova fayli bormi?"""
    doc = getattr(msg, "document", None)
    if not doc:
        return False
    fn = (doc.file_name or "").lower()
    mt = (doc.mime_type or "").lower()
    return fn.endswith(APK_EXTS) or "android.package" in mt or "vnd.android" in mt

def is_arabic_or_chinese(text: str) -> bool:
    ranges = (
        (0x0600, 0x06FF),  # Arabic
        (0x0750, 0x077F),  # Arabic Supplement
        (0x08A0, 0x08FF),  # Arabic Extended-A
        (0xFB50, 0xFDFF),  # Arabic Presentation Forms-A
        (0xFE70, 0xFEFF),  # Arabic Presentation Forms-B
        (0x4E00, 0x9FFF),  # CJK Unified
        (0x3400, 0x4DBF),  # CJK Extension A
        (0x3040, 0x30FF),  # Japanese kana
    )
    for char in text:
        cp = ord(char)
        for lo, hi in ranges:
            if lo <= cp <= hi:
                return True
    return False

# ──────────────────────────────────────────────
# Kik va o'chirish
# ──────────────────────────────────────────────

async def bot_can_moderate(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> bool:
    """Bot guruhda admin va ban/o'chirish huquqiga egami?"""
    try:
        me = await context.bot.get_chat_member(chat_id, context.bot.id)
    except Exception:
        return False
    if me.status != ChatMember.ADMINISTRATOR:
        return False
    return bool(getattr(me, "can_delete_messages", False)
                and getattr(me, "can_restrict_members", False))


async def send_recruit_message(context: ContextTypes.DEFAULT_TYPE, chat_id: int):
    """Bot admin bo'lmaganda: 'meni admin qiling' chaqirig'i (5 daqiqada 1 marta)."""
    import time
    now = time.time()
    if now - recruit_throttle.get(chat_id, 0) < 300:   # spam bo'lmasligi uchun
        return
    recruit_throttle[chat_id] = now

    bot_username = context.bot.username
    admin_url = (
        f"https://t.me/{bot_username}"
        f"?startgroup=true&admin=delete_messages+restrict_members"
    )
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("👮 Meni admin qiling", url=admin_url)],
        [InlineKeyboardButton("📢 @tezweb_uz", url="https://t.me/tezweb_uz")],
    ])
    text = (
        "⚠️ *Diqqat!* Guruhda spam yoki APK fayl aniqlandi, "
        "lekin menda o'chirish huquqi yo'q.\n\n"
        "👮 *Meni admin qiling* — shunda men:\n"
        "✅ Bunday foydalanuvchilarni avtomatik chiqaraman\n"
        "✅ APK (virusli ilova) fayllarni bloklayman\n"
        "✅ Uyatsiz so'zli profillardan himoya qilaman\n\n"
        "👇 Admin qilish uchun tugmani bosing:"
    )
    try:
        await context.bot.send_message(chat_id, text, parse_mode="Markdown", reply_markup=keyboard)
    except Exception as e:
        logger.error("Recruit xabar xato %s: %s", chat_id, e)


async def delete_and_kick(update: Update, context: ContextTypes.DEFAULT_TYPE, reason: str,
                          hard_ban: bool = False, red: bool = False):
    """hard_ban=True — butunlay bloklash (unban QILMAYMIZ, qayta kira olmaydi = QORA RO'YXAT).
    red=True — 🔴 qizil ogohlantirish + adminlarga shaxsiy signal."""
    chat = update.effective_chat
    user = update.effective_user
    msg  = update.effective_message
    if not user:
        return

    # Bot admin emas (yoki huquqi yetarli emas) — kik qila olmaymiz.
    # Buning o'rniga guruhga "meni admin qiling" chaqirig'ini yuboramiz.
    if not await bot_can_moderate(context, chat.id):
        await send_recruit_message(context, chat.id)
        return

    display_name = md(user.first_name or "user")
    username     = f"@{user.username}" if user.username else "—"
    uid          = user.id

    if msg:
        try:
            await msg.delete()
        except Exception:
            pass

    try:
        await context.bot.ban_chat_member(chat.id, user.id)
        if not hard_ban:
            await context.bot.unban_chat_member(chat.id, user.id)   # oddiy kik — qayta kira oladi
        # hard_ban: unban YO'Q → butunlay bloklangan (qora ro'yxat)
    except Exception:
        pass

    add_kick_stat(chat.id)

    bot_username = context.bot.username
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Guruhga qo'shish", url=f"https://t.me/{bot_username}?startgroup=true")],
        [InlineKeyboardButton("📢 @tezweb_uz", url="https://t.me/tezweb_uz")],
    ])

    if "APK" in reason:
        # APK uchun — jim banlash emas, balki ogohlantirish/ma'rifat
        body = (
            f"🚨 *DIQQAT! VIRUSLI FAYL!* 🚨\n\n"
            f"❌ Yuqorida *APK fayl* yuborildi — bu VIRUS bo'lishi mumkin!\n"
            f"📵 *Hech qachon .apk fayllarni o'rnatmang* —\n"
            f"aks holda Telegram va bank kartangiz *o'g'irlanadi!*\n\n"
            f"⚠️ Никогда не устанавливайте .apk из чатов — это угон аккаунта!\n\n"
            f"👢 Yuboruvchi chiqarib yuborildi:\n"
            f"👤 {md(username)}  |  🆔 `{uid}`"
        )
    elif red:
        # 🔴 Bot-reklama spam — qizil belgi + butunlay bloklandi (qora ro'yxat)
        body = (
            f"🔴 *QORA RO'YXATGA TUSHDI!* 🔴\n\n"
            f"🚫 *Bot-reklama spam* aniqlandi — begona botlar reklama qilindi.\n"
            f"Bu reyd-chaqiriq, shuning uchun user *butunlay* bloklandi.\n\n"
            f"👤 *{display_name}*  |  {md(username)}\n"
            f"🆔 ID: `{uid}`\n"
            f"⛔️ Guruhga *qayta kira olmaydi*.\n"
            f"↩️ Xato bo'lsa, admin: `/blacklist remove {uid}`"
        )
    else:
        body = (
            f"🚫 *{display_name}* guruh qoidalarini buzdi!\n"
            f"👤 Username: {md(username)}\n"
            f"🆔 ID: `{uid}`\n"
            f"📌 Sabab: {md(reason)}\n"
            f"👢 Foydalanuvchi guruhdan chiqarib yuborildi."
        )

    # Reyd paytida (chat muzlatilgan) yoki ketma-ket banlarda bildirishnoma YUBORMAYMIZ —
    # aks holda bot o'zi chatni flood qiladi va Telegram limitiga (429) uriladi.
    import time
    _now = time.time()
    if (chat.id not in locked_chats) and (_now - notice_throttle.get(chat.id, 0) >= 12):
        notice_throttle[chat.id] = _now
        notice = await context.bot.send_message(
            chat_id=chat.id,
            text=(
                f"{body}\n\n"
                f"🛡 Guruhingizda spam ko'pmi? Meni qo'shing — "
                f"spamdan 24/7 himoya qilaman!"
            ),
            parse_mode="Markdown",
            reply_markup=keyboard
        )

        async def delete_notice():
            await asyncio.sleep(300)  # 5 daqiqa
            try:
                await notice.delete()
            except Exception:
                pass

        _spawn(delete_notice())

    # Qora ro'yxat hodisasi — adminlarga shaxsiy 🔴 signal (guruh xabari o'chsa ham qoladi)
    if red:
        for admin_id in ADMIN_IDS:
            try:
                await context.bot.send_message(
                    admin_id,
                    f"🔴 *Qora ro'yxat* — «{md(chat.title or str(chat.id))}»\n"
                    f"👤 {display_name}  |  {md(username)}\n"
                    f"🆔 `{uid}`\n"
                    f"📌 {md(reason)}\n"
                    f"↩️ Qaytarish: `/blacklist remove {uid}`",
                    parse_mode="Markdown",
                )
            except Exception:
                pass

    logger.info("Kicked: @%s (id=%s) | %s | %s%s",
                user.username, uid, chat.title, reason, " [HARD-BAN/ЧС]" if hard_ban else "")

# ──────────────────────────────────────────────
# Antiflood / Slowmode tekshirish
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

    options = [answer, wrong1, wrong2]
    random.shuffle(options)

    keyboard = InlineKeyboardMarkup([[
        InlineKeyboardButton(str(opt), callback_data=f"cap_{user_id}_{opt}")
        for opt in options
    ]])

    msg = await context.bot.send_message(
        chat_id=chat_id,
        text=f"👋 Xush kelibsiz, {md(name)}!\n\n"
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
            captcha_pending.get(chat_id, {}).pop(user_id, None)
            try:
                await context.bot.ban_chat_member(chat_id, user_id)
                await context.bot.unban_chat_member(chat_id, user_id)
                await msg.delete()
            except Exception:
                pass

    _spawn(captcha_timeout())

# ──────────────────────────────────────────────
# Yangi a'zo
# ──────────────────────────────────────────────

async def handle_new_member(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    humans = [m for m in (update.message.new_chat_members or []) if not m.is_bot]

    # ── ANTIREYD: a'zolar oqimini kuzatamiz; keskin sakrash = reyd → chatni muzlatamiz ──
    if SETTINGS.get("antiraid") and humans:
        import time
        now = time.time()
        window = SETTINGS.get("raid_join_window", 30)
        jt = [t for t in join_tracker[chat_id] if now - t < window]
        jt.extend([now] * len(humans))
        join_tracker[chat_id] = jt
        if len(jt) >= SETTINGS.get("raid_join_threshold", 8) and chat_id not in locked_chats:
            await trigger_raid_lock(context, chat_id, len(jt))
            return   # reyd aniqlandi: salom/kapcha yubormaymiz, chat muzlatildi

    if chat_id in locked_chats:
        return   # chat muzlatilgan (reyd davom etmoqda) — yangilarga salom/kapcha yubormaymiz

    for member in humans:
        # Qora ro'yxatdagi odam qayta kirmoqchimi? — salom/kapcha yo'q, darhol chiqaramiz
        if member.id in BLACKLIST:
            if await bot_can_moderate(context, chat_id):
                try:
                    await context.bot.ban_chat_member(chat_id, member.id)   # hard-ban, unban yo'q
                except Exception:
                    pass
            logger.info("Qora ro'yxatdagi user %s kirishda bloklandi (%s)", member.id, chat_id)
            continue

        name = f"@{member.username}" if member.username else (member.first_name or "user")

        if SETTINGS.get("captcha"):
            # Avval mute qilamiz — kapcha haqiqatdan ishlashi uchun
            try:
                await context.bot.restrict_chat_member(chat_id, member.id, permissions=MUTED_PERMS)
            except Exception:
                logger.warning("Mute qilolmadim (admin huquqi yo'qmi?): %s", member.id)
            await send_captcha(update, context, member.id, chat_id, name)
        else:
            text = (
                f"👋 Xush kelibsiz, {md(name)}!\n\n"
                f"Bu *TezWeb.uz* rasmiy muhokama guruhimiz.\n\n"
                f"❓ Savol berish uchun xabar oxiriga *?* qo'ying\n"
                f"yoki botning xabariga reply qiling.\n\n"
                f"📢 Kanal: @tezweb_uz\n"
                f"🌐 tezweb.uz | 📩 @Shohdollar22"
            )
            await context.bot.send_message(chat_id, text, parse_mode="Markdown")

# ──────────────────────────────────────────────
# Antireyd: chatni muzlatish / ochish
# ──────────────────────────────────────────────

async def lock_chat(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> bool:
    """Guruhni muzlatadi: adminlardan tashqari hamma yoza olmaydi."""
    try:
        await context.bot.set_chat_permissions(chat_id, LOCKED_PERMS)
        locked_chats[chat_id] = True
        return True
    except Exception:
        logger.exception("lock_chat xato: %s", chat_id)
        return False


async def unlock_chat(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> bool:
    """Guruhni ochadi: yozishga ruxsat qaytaradi."""
    try:
        await context.bot.set_chat_permissions(chat_id, OPEN_PERMS)
        locked_chats.pop(chat_id, None)
        return True
    except Exception:
        logger.exception("unlock_chat xato: %s", chat_id)
        return False


async def trigger_raid_lock(context: ContextTypes.DEFAULT_TYPE, chat_id: int, joined: int):
    """Reyd aniqlandi → avto-muzlatish + adminlarga signal + avto-ochish."""
    if not await bot_can_moderate(context, chat_id):
        await send_recruit_message(context, chat_id)   # admin huquqi yo'q — chaqiramiz
        return
    if not await lock_chat(context, chat_id):
        return
    logger.warning("ANTIREYD: chat %s muzlatildi (%s a'zo oqimi)", chat_id, joined)
    try:
        title = (await context.bot.get_chat(chat_id)).title or str(chat_id)
    except Exception:
        title = str(chat_id)
    mins = SETTINGS.get("raid_autounlock_min", 10)
    # Guruhga BITTA qisqa ogohlantirish (flood emas)
    try:
        await context.bot.send_message(
            chat_id,
            "🛡 *Reyd aniqlandi — guruh vaqtincha muzlatildi.*\n"
            "Tez orada avtomatik ochiladi. Adminlar /unlock bilan qo'lda ocha oladi.",
            parse_mode="Markdown",
        )
    except Exception:
        pass
    # Adminlarga shaxsiy signal
    for admin_id in ADMIN_IDS:
        try:
            await context.bot.send_message(
                admin_id,
                f"⚠️ *REYD!* «{md(str(title))}» guruhiga {joined}+ a'zo qisqa vaqtda kirdi.\n"
                f"Guruh *muzlatildi*. {mins} daqiqadan keyin avto-ochiladi (yoki /unlock).",
                parse_mode="Markdown",
            )
        except Exception:
            pass
    # Avto-ochish
    if mins and mins > 0:
        async def _auto_unlock():
            await asyncio.sleep(mins * 60)
            if chat_id in locked_chats:
                await unlock_chat(context, chat_id)
                try:
                    await context.bot.send_message(chat_id, "✅ Guruh ochildi. Reyd tugadi.")
                except Exception:
                    pass
        _spawn(_auto_unlock())


async def cmd_lock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type == "private":
        await update.message.reply_text("Bu buyruq guruhda ishlaydi.")
        return
    if not (is_super_admin(update.effective_user.id) or await is_admin_in_chat(update, context)):
        return
    chat_id = update.effective_chat.id
    if not await bot_can_moderate(context, chat_id):
        await send_recruit_message(context, chat_id)
        return
    if await lock_chat(context, chat_id):
        await update.message.reply_text("🔒 Guruh muzlatildi. Ochish: /unlock")


async def cmd_unlock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type == "private":
        await update.message.reply_text("Bu buyruq guruhda ishlaydi.")
        return
    if not (is_super_admin(update.effective_user.id) or await is_admin_in_chat(update, context)):
        return
    chat_id = update.effective_chat.id
    if await unlock_chat(context, chat_id):
        await update.message.reply_text("🔓 Guruh ochildi. Hamma yoza oladi.")


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
        captcha_pending.get(chat_id, {}).pop(user_id, None)
        # Unmute — yozishga ruxsat qaytaramiz
        try:
            await context.bot.restrict_chat_member(chat_id, user_id, permissions=UNMUTED_PERMS)
        except Exception:
            logger.warning("Unmute qilolmadim: %s", user_id)
        try:
            await query.message.delete()
        except Exception:
            pass
    else:
        await query.answer("❌ Noto'g'ri! Siz bot sifatida aniqlangiz.")
        captcha_pending.get(chat_id, {}).pop(user_id, None)
        try:
            await context.bot.ban_chat_member(chat_id, user_id)
            await context.bot.unban_chat_member(chat_id, user_id)
            await query.message.delete()
        except Exception:
            pass

# ──────────────────────────────────────────────
# Xabarlarni tekshirish (umumiy pipeline)
# ──────────────────────────────────────────────

async def _should_skip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    chat = update.effective_chat
    if chat is None or chat.type == "private":
        return True
    msg = update.effective_message
    if msg is None:
        return True
    if msg.sender_chat:
        return True
    user = update.effective_user
    if not user:
        return True
    if user.id in WHITELIST:
        return True
    if await is_admin_in_chat(update, context):
        return True
    return False

async def moderate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Matn yoki caption ustidan spam-tekshiruv. Chora ko'rilsa True."""
    msg = update.effective_message
    if msg is None:
        return False
    content = msg.text or msg.caption or ""
    chat_id = update.effective_chat.id
    user    = update.effective_user

    # ── ENG YUQORI USTUVORLIK: qora ro'yxat ──
    # Allaqachon qora ro'yxatdagi odam (boshqa guruhda tutilган) — darhol butunlay chiqaramiz
    if user.id in BLACKLIST:
        await delete_and_kick(update, context, "Qora ro'yxatdagi foydalanuvchi", hard_ban=True)
        return True

    # Bot-reklama / referal-farm spam («/start 71 @xxxbot» + @...bot) → 🔴 qora ro'yxat
    if is_bot_promo_spam(content):
        BLACKLIST.add(user.id)
        save_blacklist(BLACKLIST)
        await delete_and_kick(update, context, "Bot-reklama spam (referal-farm)",
                              hard_ban=True, red=True)
        return True

    # Uyatsiz so'zli profil (ism / familiya / username qora ro'yxatda bo'lsa)
    profile = f"{user.first_name or ''} {user.last_name or ''} {user.username or ''}"
    if contains_keyword(profile):
        await delete_and_kick(update, context, "Uyatsiz so'zli profil")
        return True

    # Antiflood
    if SETTINGS.get("antiflood") and check_flood(chat_id, user.id):
        await delete_and_kick(update, context, "Flood (juda ko'p xabar)")
        return True

    # Slowmode
    if SETTINGS.get("slowmode") and check_slowmode(chat_id, user.id):
        try:
            await msg.delete()
        except Exception:
            pass
        return True

    if content:
        # Arabic/Chinese bloklash
        if SETTINGS.get("block_arabic") and is_arabic_or_chinese(content):
            await delete_and_kick(update, context, "Taqiqlangan til (arab/xitoy)")
            return True
        # Havolalar
        if SETTINGS.get("block_links") and (URL_REGEX.search(content) or MENTION_REGEX.search(content)):
            await delete_and_kick(update, context, "Xabar ichida havola (link) bor")
            return True
        # Kalit so'zlar
        if contains_keyword(content):
            await delete_and_kick(update, context, "Taqiqlangan so'z aniqlandi")
            return True

    return False

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if await _should_skip(update, context):
        return
    await moderate(update, context)

async def handle_media(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if await _should_skip(update, context):
        return
    msg = update.effective_message

    # APK / xavfli ilova fayli — sozlamadan qat'i nazar, HAR DOIM darhol ban
    if is_apk(msg):
        await delete_and_kick(update, context, "APK fayl (xavfli ilova) yuborildi")
        return

    # Tur bo'yicha qattiq bloklash
    if msg.photo and SETTINGS.get("block_photos"):
        await delete_and_kick(update, context, "Guruhda rasm yuborish taqiqlangan")
        return
    if (msg.video or msg.video_note or msg.animation) and SETTINGS.get("block_videos"):
        await delete_and_kick(update, context, "Guruhda video yuborish taqiqlangan")
        return

    # Bloklanmagan media bo'lsa — caption ichidagi havola/so'zni tekshiramiz
    await moderate(update, context)

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
            "*Qora ro'yxat (bot-spam):*\n"
            "`/blacklist list` — ko'rish\n"
            "`/blacklist remove ID` — chiqarish\n\n"
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
        f"{on if s.get('block_arabic', False) else off} Arab/xitoy bloklash\n"
        f"{on if s.get('antiraid', True) else off} Antireyd (reyd paytida avto-muzlatish)\n"
        f"🔴 Bot-reklama spam → avto qora ro'yxat: *doim yoqiq* ({len(BLACKLIST)} ta ЧС)\n\n"
        f"*O'zgartirish:* `/toggle links/photos/videos/antiflood/captcha/slowmode/arabic/antiraid`\n"
        f"🔒 Qo'lda: guruhda `/lock` (muzlatish) va `/unlock` (ochish)\n"
        f"⛔️ Qora ro'yxat: `/blacklist list` · `/blacklist remove ID`"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Ishlatish: /toggle links|photos|videos|antiflood|captcha|slowmode|arabic|antiraid")
        return

    key_map = {
        "links": "block_links", "photos": "block_photos",
        "videos": "block_videos", "antiflood": "antiflood",
        "captcha": "captcha", "slowmode": "slowmode",
        "arabic": "block_arabic", "antiraid": "antiraid",
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
        try:
            chat = await context.bot.get_chat(int(gid))
            name = chat.title or gid
        except Exception:
            name = gid
        text += f"{i}. {md(str(name))} — {count} ta\n"
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


async def cmd_blacklist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Qora ro'yxatni boshqarish: ko'rish / qo'lda qo'shish / chiqarish (xato bo'lsa)."""
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text(
            f"⛔️ *Qora ro'yxat:* {len(BLACKLIST)} ta\n\n"
            "Ishlatish:\n"
            "`/blacklist list` — ko'rish\n"
            "`/blacklist remove ID` — chiqarish (xato bo'lsa)\n"
            "`/blacklist add ID` — qo'lda qo'shish",
            parse_mode="Markdown")
        return

    action = context.args[0].lower()
    if action == "list":
        if not BLACKLIST:
            await update.message.reply_text("Qora ro'yxat bo'sh.")
        else:
            ids = sorted(BLACKLIST)
            await update.message.reply_text(
                f"⛔️ Qora ro'yxat ({len(ids)}):\n" + "\n".join(f"• `{u}`" for u in ids),
                parse_mode="Markdown")
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
        BLACKLIST.add(uid)
        save_blacklist(BLACKLIST)
        await update.message.reply_text(f"⛔️ {uid} qora ro'yxatga qo'shildi.")
    elif action == "remove":
        BLACKLIST.discard(uid)
        save_blacklist(BLACKLIST)
        await update.message.reply_text(f"✅ {uid} qora ro'yxatdan chiqarildi.")
    else:
        await update.message.reply_text("Noma'lum amal. list | add | remove")


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
    await update.message.reply_text(f"✅ *{md(chat_title)}* reklama royxatiga qoshildi!", parse_mode="Markdown")


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
    await update.message.reply_text(f"Ochirildi: *{md(chat_title)}*", parse_mode="Markdown")


async def cmd_listgroups(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    if not GROUPS:
        await update.message.reply_text("Reklama guruhlari royxati bosh.\n\nQoshish: guruhga boring va /addgroup yuboring.")
        return

    lines = []
    for chat_id in GROUPS:
        try:
            chat = await context.bot.get_chat(chat_id)
            name = chat.title or str(chat_id)
            username = f" @{chat.username}" if chat.username else ""
            lines.append(f"• {name}{username}\n  ID: {chat_id}")
        except Exception:
            lines.append(f"• ID: {chat_id} (nom olinmadi)")

    await update.message.reply_text(
        f"Guruhlar: {len(GROUPS)} ta\n\n" + "\n\n".join(lines)
    )


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
    groups = stats.get("groups", {})
    sorted_groups = sorted(groups.items(), key=lambda x: x[1], reverse=True)[:5]

    top_text = ""
    for i, (gid, count) in enumerate(sorted_groups, 1):
        try:
            chat = await bot.get_chat(int(gid))
            name = chat.title or gid
        except Exception:
            name = gid
        top_text += f"{i}. {md(str(name))} — {count} ta\n"

    text = (
        f"📊 *Kunlik hisobot — {dt.date.today().isoformat()}*\n\n"
        f"🦠 Bugun kiklangan: *{stats.get('today', 0)}* ta spam\n"
        f"📆 Bu hafta: *{stats.get('week', 0)}* ta spam\n"
        f"📈 Jami barcha vaqt: *{stats.get('total', 0)}* ta\n\n"
        f"🏆 *Eng faol guruhlar:*\n{top_text}\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"😤 Siz ham charchadingizmi uyatsiz spamlardan?\n"
        f"Unda sizga faqat *TezWeb Antispam* yordam bera oladi!\n"
        f"Guruhingizga qo'shing va admin qilib qo'ying 👇\n\n"
        f"tezweb.uz | @tezweb_uz"
    )

    # Adminga yuborish
    for admin_id in ADMIN_IDS:
        try:
            await bot.send_message(chat_id=admin_id, text=text, parse_mode="Markdown")
        except Exception:
            pass

    # Barcha guruhlarga yuborish va 3 daqiqadan so'ng o'chirish
    bot_username = (await bot.get_me()).username
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Guruhga qo'shish", url=f"https://t.me/{bot_username}?startgroup=true")],
        [InlineKeyboardButton("📢 @tezweb_uz", url="https://t.me/tezweb_uz")],
    ])
    for chat_id in list(GROUPS):
        try:
            msg = await bot.send_message(chat_id=chat_id, text=text, parse_mode="Markdown", reply_markup=keyboard)
            await asyncio.sleep(180)
            try:
                await bot.delete_message(chat_id=chat_id, message_id=msg.message_id)
            except Exception:
                pass
        except Exception as e:
            logger.error("Hisobot xato %s: %s", chat_id, e)


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
    app.add_handler(CommandHandler("blacklist",  cmd_blacklist))
    app.add_handler(CommandHandler("addgroup",   cmd_addgroup))
    app.add_handler(CommandHandler("removegroup",cmd_removegroup))
    app.add_handler(CommandHandler("listgroups", cmd_listgroups))
    app.add_handler(CommandHandler("lock",       cmd_lock))
    app.add_handler(CommandHandler("unlock",     cmd_unlock))

    # Yangi a'zo
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, handle_new_member))

    # Matn (yangi + tahrirlangan — effective_message ishlatilgani uchun ikkalasi ham)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    # Media (caption ham tekshiriladi)
    media_filter = (
        filters.PHOTO | filters.VIDEO | filters.VIDEO_NOTE | filters.ANIMATION |
        filters.Document.ALL | filters.AUDIO | filters.VOICE
    )
    app.add_handler(MessageHandler(media_filter, handle_media))

    # Callback (kapcha)
    from telegram.ext import CallbackQueryHandler
    app.add_handler(CallbackQueryHandler(handle_captcha_callback, pattern=r"^cap_"))

    # Jadval
    jq = app.job_queue
    jq.run_daily(lambda ctx: _spawn(send_promo(ctx.bot)),
                 time=dt.time(2, 0, 0))    # 7:00 Toshkent
    jq.run_daily(lambda ctx: _spawn(send_promo(ctx.bot)),
                 time=dt.time(16, 0, 0))   # 21:00 Toshkent
    jq.run_daily(lambda ctx: _spawn(send_daily_report(ctx.bot)),
                 time=dt.time(17, 0, 0))   # 22:00 Toshkent
    jq.run_daily(lambda ctx: _spawn(send_weekly_report(ctx.bot)),
                 time=dt.time(18, 0, 0),   # 23:00 Toshkent
                 days=(6,))                # 6 = Yakshanba

    logger.info("✅ TezWeb Antispam Bot ishga tushdi!")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
