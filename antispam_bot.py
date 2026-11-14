"""
Telegram Antispam Bot — TezWeb.uz
Barcha funksiyalar: antispam, antiflood, kapcha, whitelist, statistika, hisobotlar

Xavfsizlik tuzatishlari (security-fixed):
- Markdown-injection: foydalanuvchi ismi escape qilinadi (escape_markdown)
- Kapcha endi haqiqatdan mute qiladi (restrict_chat_member), to'g'ri javobdan keyin unmute
- Edited (tahrirlangan) xabarlar ham tekshiriladi (effective_message ishlatiladi)
- Caption (rasm/video/fayl ostidagi matn) ham havola/so'zga tekshiriladi + ko'proq media turi
- SQLite tranzaksiyalari — holat buzilishi va parallel yozishdan himoya
- Arab/CJK diapazonlari kengaytirildi
- captcha_pending uchun xavfsiz .pop()
"""

import asyncio
import datetime as dt
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
import zipfile
from collections import defaultdict
from pathlib import Path

from telegram import (
    ChatMember,
    ChatPermissions,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.ext import (
    AIORateLimiter,
    Application,
    ApplicationHandlerStop,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from telegram.helpers import escape_markdown

# ──────────────────────────────────────────────
# Sozlamalar
# ──────────────────────────────────────────────

BOT_TOKEN  = os.environ.get("BOT_TOKEN", "")
DATA_DIR   = Path(os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_FILE = DATA_DIR / "bot_state.sqlite3"

KEYWORDS_FILE  = str(DATA_DIR / "keywords.json")
SETTINGS_FILE  = str(DATA_DIR / "settings.json")
GROUPS_FILE    = str(DATA_DIR / "groups.json")
STATS_FILE     = str(DATA_DIR / "stats.json")
WHITELIST_FILE = str(DATA_DIR / "whitelist.json")
SLOWMODE_FILE  = str(DATA_DIR / "slowmode.json")
BLACKLIST_FILE = str(DATA_DIR / "blacklist.json")
ACTION_NOTICES_FILE = str(DATA_DIR / "action_notices.json")
WARNED_USERS_FILE = str(DATA_DIR / "warned_users.json")
LOCK_STATE_FILE = str(DATA_DIR / "locked_chats.json")

_admin_ids_raw = os.environ.get("ADMIN_IDS", "6038976942,2018064843")
ADMIN_IDS = {
    int(value.strip()) for value in _admin_ids_raw.split(",")
    if value.strip().lstrip("-").isdigit()
}

logging.basicConfig(format="%(asctime)s | %(levelname)s | %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)
try:
    os.chmod(DATA_DIR, 0o700)
except OSError as exc:
    logger.debug("DATA_DIR chmod bajarilmadi: %s", exc)

# httpx har bir so'rov URL'ini (ichida token bor!) INFO darajada log qiladi —
# uni WARNING ga ko'taramiz, shunda token logga umuman tushmaydi.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


class _RedactToken(logging.Filter):
    """Qo'shimcha himoya: token biror joyda logga tushsa ham — yashiramiz."""
    @staticmethod
    def _redact(value):
        if isinstance(value, str):
            return value.replace(BOT_TOKEN, "***TOKEN***") if BOT_TOKEN else value
        if isinstance(value, tuple):
            return tuple(_RedactToken._redact(item) for item in value)
        if isinstance(value, list):
            return [_RedactToken._redact(item) for item in value]
        if isinstance(value, dict):
            return {
                _RedactToken._redact(key): _RedactToken._redact(item)
                for key, item in value.items()
            }
        return value

    def filter(self, record):
        if not BOT_TOKEN:
            return True
        record.msg = self._redact(record.msg)
        record.args = self._redact(record.args)
        return True


for _h in logging.getLogger().handlers:
    _h.addFilter(_RedactToken())

URL_REGEX = re.compile(
    r'(?:https?|hxxps?|tg)\s*:\s*//\S+'
    r'|(?:www\.)\S+'
    r'|(?:t|telegram)\s*(?:\.|\[\.\]|\(\.\)|\{\.\})\s*(?:me|dog)(?:/\S*)?'
    r'|\b(?:[a-z0-9-]+\.)+(?:com|net|org|uz|ru|io|me|xyz|top|site|online|shop|info|biz)\b',
    re.IGNORECASE,
)
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
    text = clean_text(text)
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

# Ommaviy buyruq va servis xabarlarini flood qilishdan himoya.
command_throttle: dict = {}
notice_throttle: dict = {}
_notice_locks = defaultdict(asyncio.Lock)

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
    def _done(completed):
        _bg_tasks.discard(completed)
        if completed.cancelled():
            return
        try:
            completed.result()
        except Exception:
            logger.exception("Background task xato")
    task.add_done_callback(_done)
    return task

def md(text: str) -> str:
    """Markdown (v1) uchun foydalanuvchi matnini xavfsiz qilish."""
    return escape_markdown(text or "", version=1)

# ──────────────────────────────────────────────
# Matn tozalash
# ──────────────────────────────────────────────

def clean_text(text: str) -> str:
    invisible = [
        "\u200b", "\u200c", "\u200d", "\u200e", "\u200f",
        "\ufe0f", "\u2060", "\ufeff", "\u00ad", "\u034f",
    ]
    for char in invisible:
        text = text.replace(char, '')
    return unicodedata.normalize('NFKC', text).lower()

# ──────────────────────────────────────────────
# Saqlash funksiyalari (SQLite + eski JSON fayllardan avtomatik migratsiya)
# ──────────────────────────────────────────────

_DB_LOCK = threading.RLock()

def _init_database():
    with _DB_LOCK, sqlite3.connect(DB_FILE, timeout=15) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS state ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)"
        )
    try:
        os.chmod(DB_FILE, 0o600)
    except OSError:
        pass

def _state_key(path) -> str:
    return Path(path).name

_init_database()

def load_json(path, default):
    try:
        with _DB_LOCK, sqlite3.connect(DB_FILE, timeout=15) as conn:
            row = conn.execute(
                "SELECT value FROM state WHERE key = ?", (_state_key(path),),
            ).fetchone()
        if row:
            return json.loads(row[0])

        # Birinchi ishga tushishda eski JSON ma'lumotlarini yo'qotmaymiz.
        legacy_path = Path(path)
        if legacy_path.exists():
            with open(legacy_path, "r", encoding="utf-8") as f:
                migrated = json.load(f)
            save_json(path, migrated)
            return migrated
    except Exception:
        logger.exception("Holatni yuklash xatosi: %s", path)
    return default

def save_json(path, data):
    """Kichik atomar SQLite tranzaksiyasi; xato bo'lsa False qaytaradi."""
    try:
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        with _DB_LOCK, sqlite3.connect(DB_FILE, timeout=15) as conn:
            conn.execute(
                "INSERT INTO state(key, value, updated_at) VALUES(?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated_at=excluded.updated_at",
                (_state_key(path), payload, int(time.time())),
            )
        return True
    except Exception:
        logger.exception("Holatni saqlash xatosi: %s", path)
        return False

def load_keywords() -> set:
    saved = load_json(KEYWORDS_FILE, [])
    return {str(value)[:256] for value in saved} if isinstance(saved, list) else set()

def save_keywords(kw: set):
    save_json(KEYWORDS_FILE, list(kw))

def load_settings() -> dict:
    defaults = {
        "block_links": True, "block_photos": True,
        "block_videos": True, "block_files": True, "antiflood": True,
        "captcha": False, "slowmode": False,
        "block_arabic": True, "slowmode_seconds": 60,
        "flood_limit": 5, "flood_seconds": 10,
        # Antireyd: keskin a'zolar oqimi → chatni avtomatik muzlatish
        "antiraid": True, "raid_join_threshold": 8, "raid_join_window": 30,
        "raid_autounlock_min": 10,
    }
    saved = load_json(SETTINGS_FILE, {})
    if isinstance(saved, dict):
        defaults.update(saved)
    defaults["slowmode_seconds"] = max(1, min(int(defaults["slowmode_seconds"]), 86400))
    defaults["flood_limit"] = max(2, min(int(defaults["flood_limit"]), 100))
    defaults["flood_seconds"] = max(1, min(int(defaults["flood_seconds"]), 3600))
    defaults["raid_join_threshold"] = max(3, min(int(defaults["raid_join_threshold"]), 1000))
    defaults["raid_join_window"] = max(5, min(int(defaults["raid_join_window"]), 3600))
    defaults["raid_autounlock_min"] = max(0, min(int(defaults["raid_autounlock_min"]), 1440))
    return defaults

def save_settings(s: dict):
    save_json(SETTINGS_FILE, s)

def load_groups() -> set:
    saved = load_json(GROUPS_FILE, [])
    if not isinstance(saved, list):
        return set()
    result = set()
    for value in saved:
        try:
            result.add(int(value))
        except (TypeError, ValueError):
            continue
    return result

def save_groups(g: set):
    save_json(GROUPS_FILE, list(g))

def load_stats() -> dict:
    default = {"total": 0, "today": 0, "week": 0, "last_reset": "", "last_week_reset": "", "groups": {}}
    saved = load_json(STATS_FILE, default)
    return saved if isinstance(saved, dict) else default

def save_stats(s: dict):
    save_json(STATS_FILE, s)

def load_whitelist() -> set:
    return _load_int_set(WHITELIST_FILE)

def save_whitelist(w: set):
    save_json(WHITELIST_FILE, list(w))

def load_blacklist() -> set:
    return _load_int_set(BLACKLIST_FILE)

def save_blacklist(b: set):
    save_json(BLACKLIST_FILE, list(b))

def _load_int_set(path) -> set:
    saved = load_json(path, [])
    if not isinstance(saved, list):
        return set()
    result = set()
    for value in saved:
        try:
            result.add(int(value))
        except (TypeError, ValueError):
            continue
    return result

def load_action_notices() -> dict:
    saved = load_json(ACTION_NOTICES_FILE, {})
    try:
        return {int(chat_id): int(message_id) for chat_id, message_id in saved.items()}
    except (AttributeError, TypeError, ValueError):
        return {}

def save_action_notices(notices: dict):
    save_json(ACTION_NOTICES_FILE, notices)

WARN_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_WARNED_USERS = 50_000

def load_warned_users() -> dict:
    saved = load_json(WARNED_USERS_FILE, {})
    now = time.time()
    if isinstance(saved, list):  # eski format
        return {str(key): now for key in saved[-MAX_WARNED_USERS:]}
    if not isinstance(saved, dict):
        return {}
    result = {}
    for key, timestamp in saved.items():
        try:
            timestamp = float(timestamp)
        except (TypeError, ValueError):
            continue
        if now - timestamp < WARN_TTL_SECONDS:
            result[str(key)] = timestamp
    return dict(sorted(result.items(), key=lambda item: item[1])[-MAX_WARNED_USERS:])

def save_warned_users(users: dict):
    save_json(WARNED_USERS_FILE, users)

def load_locked_chats() -> dict:
    saved = load_json(LOCK_STATE_FILE, {})
    if not isinstance(saved, dict):
        return {}
    result = {}
    for chat_id, state in saved.items():
        if not isinstance(state, dict) or not isinstance(state.get("permissions"), dict):
            continue
        try:
            result[int(chat_id)] = state
        except (TypeError, ValueError):
            continue
    return result

def save_locked_chats():
    save_json(LOCK_STATE_FILE, locked_chats)

KEYWORDS  = load_keywords()
SETTINGS  = load_settings()
GROUPS    = load_groups()
WHITELIST = load_whitelist()
BLACKLIST = load_blacklist()   # qattiq qoida buzgan, butunlay bloklangan user ID lar
# Guruhdagi oxirgi reklama/amal natijasi: {chat_id: message_id}.
# Yangi reklama yoki natija chiqqanda eskisi o'chadi, yangisi keyingisigacha qoladi.
LAST_ACTION_NOTICES = load_action_notices()
if len(LAST_ACTION_NOTICES) > 10_000:
    LAST_ACTION_NOTICES = dict(list(LAST_ACTION_NOTICES.items())[-10_000:])
# Birinchi link/video/fayl qoidabuzarligida ogohlantirilganlar: {"chat_id:user_id"}.
WARNED_USERS = load_warned_users()
locked_chats = load_locked_chats()

# ──────────────────────────────────────────────
# Statistika
# ──────────────────────────────────────────────

def add_kick_stat(chat_id: int):
    stats = load_stats()
    if not isinstance(stats.get("groups"), dict):
        stats["groups"] = {}
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

def command_allowed(update: Update, command: str, interval: int = 15) -> bool:
    """Public komandalar orqali botning o'zini flood qilishga yo'l qo'ymaydi."""
    chat = update.effective_chat
    user = update.effective_user
    if not chat or chat.type == "private" or not user:
        return True
    key = (chat.id, user.id, command)
    now = time.time()
    if now - command_throttle.get(key, 0) < interval:
        return False
    command_throttle[key] = now
    return True

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

def message_has_link(msg, content: str = "") -> bool:
    """Oddiy, yashirilgan va tugmadagi Telegram havolalarini aniqlash."""
    normalized = clean_text(content or "")
    if URL_REGEX.search(normalized) or MENTION_REGEX.search(normalized):
        return True

    # Masalan: ko'rinadigan matn "kanal", ammo TEXT_LINK ichida t.me URL bor.
    entities = list(getattr(msg, "entities", None) or [])
    entities.extend(getattr(msg, "caption_entities", None) or [])
    link_entity_types = {"url", "text_link", "mention", "text_mention"}
    for entity in entities:
        if str(getattr(entity, "type", "")).lower() in link_entity_types:
            return True
        if getattr(entity, "url", None):
            return True

    # Botlar yuborgan inline-tugmalardagi havolalarni ham o'tkazmaymiz.
    if message_has_url_button(msg):
        return True

    return False

def message_has_url_button(msg) -> bool:
    """Xabarga biriktirilgan URL-tugma bormi?"""
    reply_markup = getattr(msg, "reply_markup", None)
    for row in getattr(reply_markup, "inline_keyboard", None) or []:
        for button in row:
            if getattr(button, "url", None):
                return True
    return False

def is_advertisement_message(msg, content: str = "") -> bool:
    """Kanal posti yoki URL-tugmali media ko'rinishidagi reklamani aniqlash."""
    has_media = bool(
        getattr(msg, "photo", None)
        or getattr(msg, "video", None)
        or getattr(msg, "animation", None)
        or getattr(msg, "document", None)
    )

    # Telegram yangi versiyalarida kanal forward'i forward_origin orqali keladi.
    origin = getattr(msg, "forward_origin", None)
    origin_type = str(getattr(origin, "type", "")).lower()
    origin_chat = getattr(origin, "chat", None)
    forwarded_from_channel = (
        origin_type == "channel"
        or str(getattr(origin_chat, "type", "")).lower() == "channel"
    )

    # Eski python-telegram-bot versiyalari uchun legacy maydon.
    legacy_forward_chat = getattr(msg, "forward_from_chat", None)
    if str(getattr(legacy_forward_chat, "type", "")).lower() == "channel":
        forwarded_from_channel = True

    # URL-tugma reklamaning kuchli belgisi. Kanalдан forward qilingan media/link
    # ham reklama sifatida tekshiriladi.
    return message_has_url_button(msg) or (
        forwarded_from_channel and (has_media or message_has_link(msg, content))
    )

def is_apk(msg) -> bool:
    """Metadata bo'yicha APK/xavfli Android paketi bormi?"""
    doc = getattr(msg, "document", None)
    if not doc:
        return False
    fn = clean_text(doc.file_name or "")
    mt = (doc.mime_type or "").lower()
    return (
        fn.endswith(APK_EXTS)
        or any(f"{ext}." in fn for ext in APK_EXTS)
        or "android.package" in mt
        or "vnd.android" in mt
    )

async def is_apk_file(msg, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Metadata va kichik ZIP fayl ichki tuzilmasi bo'yicha APK tekshiruvi."""
    if is_apk(msg):
        return True
    doc = getattr(msg, "document", None)
    if not doc:
        return False
    file_size = int(getattr(doc, "file_size", 0) or 0)
    file_name = clean_text(getattr(doc, "file_name", "") or "")
    mime_type = (getattr(doc, "mime_type", "") or "").lower()
    candidate = (
        file_name.endswith((".zip", ".jar", ".bin", ".dat", ".tmp"))
        or "." not in Path(file_name).name
        or mime_type in {"application/zip", "application/octet-stream", "application/java-archive"}
    )
    # Katta/oddiy fayllar baribir block_files orqali o'chadi; download-DoS qilmaymiz.
    if not candidate or file_size <= 0 or file_size > 8 * 1024 * 1024:
        return False
    try:
        telegram_file = await context.bot.get_file(doc.file_id)
        payload = await telegram_file.download_as_bytearray()
        if not bytes(payload[:4]).startswith(b"PK"):
            return False
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = set(archive.namelist())
        return "AndroidManifest.xml" in names and any(
            name == "classes.dex" or re.fullmatch(r"classes\d+\.dex", name)
            for name in names
        )
    except (zipfile.BadZipFile, RuntimeError, OSError, ValueError):
        return False
    except Exception:
        logger.exception("APK ichki tekshiruvi bajarilmadi")
        return False

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
    matches = 0
    for char in text:
        cp = ord(char)
        for lo, hi in ranges:
            if lo <= cp <= hi:
                matches += 1
                break
        if matches >= 2:  # bitta tasodifiy belgi uchun global ЧС qilmaymiz
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


async def replace_last_group_notice(bot, chat_id: int, new_message_id: int):
    """Guruhda faqat eng yangi reklama/amal xabarini qoldiradi."""
    previous_notice_id = LAST_ACTION_NOTICES.get(chat_id)
    LAST_ACTION_NOTICES[chat_id] = new_message_id
    while len(LAST_ACTION_NOTICES) > 10_000:
        LAST_ACTION_NOTICES.pop(next(iter(LAST_ACTION_NOTICES)))
    save_action_notices(LAST_ACTION_NOTICES)
    if previous_notice_id and previous_notice_id != new_message_id:
        try:
            await bot.delete_message(
                chat_id=chat_id,
                message_id=previous_notice_id,
            )
        except Exception:
            logger.debug("Eski servis xabari allaqachon o'chgan: chat=%s msg=%s", chat_id, previous_notice_id)


async def send_rotating_action_notice(context: ContextTypes.DEFAULT_TYPE,
                                      chat_id: int, body: str):
    """Faqat eng yangi amal natijasini qoldiradi; eskisini o'chiradi."""
    if chat_id in locked_chats:
        return

    bot_username = context.bot.username
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Guruhga qo'shish", url=f"https://t.me/{bot_username}?startgroup=true")],
        [InlineKeyboardButton("📢 @tezweb_uz", url="https://t.me/tezweb_uz")],
    ])
    text = (
        f"{body}\n\n"
        f"🛡 Guruhingizda spam ko'pmi? Meni qo'shing — "
        f"spamdan 24/7 himoya qilaman!"
    )

    async with _notice_locks[chat_id]:
        now = time.time()
        previous_id = LAST_ACTION_NOTICES.get(chat_id)
        # Reyd/flood paytida yangi xabarlar bilan Telegram limitini urmaymiz:
        # mavjud servis xabarini tahrirlaymiz.
        if previous_id and now - notice_throttle.get(chat_id, 0) < 5:
            try:
                await context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=previous_id,
                    text=text,
                    parse_mode="Markdown",
                    reply_markup=keyboard,
                )
                notice_throttle[chat_id] = now
                return
            except Exception:
                logger.warning("Servis xabarini tahrirlab bo'lmadi: chat=%s", chat_id)

        notice = await context.bot.send_message(
            chat_id=chat_id,
            text=text,
            parse_mode="Markdown",
            reply_markup=keyboard,
        )
        notice_throttle[chat_id] = now
        await replace_last_group_notice(context.bot, chat_id, notice.message_id)


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
            logger.exception("Qoidabuzar xabarini o'chirib bo'lmadi: chat=%s user=%s", chat.id, uid)

    try:
        await context.bot.ban_chat_member(chat.id, user.id)
    except Exception:
        logger.exception("Foydalanuvchini ban qilib bo'lmadi: chat=%s user=%s", chat.id, uid)
        return False

    if not hard_ban:
        try:
            await context.bot.unban_chat_member(chat.id, user.id)   # oddiy kik — qayta kira oladi
        except Exception:
            # Ban muvaffaqiyatli; unban xatosi userni kuchliroq bloklab qo'yadi.
            logger.exception("Kikdan keyin unban qilib bo'lmadi: chat=%s user=%s", chat.id, uid)

    add_kick_stat(chat.id)

    if "APK" in reason:
        # APK uchun — jim banlash emas, balki ogohlantirish/ma'rifat
        body = (
            f"🚨 *DIQQAT! VIRUSLI FAYL!* 🚨\n\n"
            f"❌ Yuqorida *APK fayl* yuborildi — bu VIRUS bo'lishi mumkin!\n"
            f"📵 *Hech qachon .apk fayllarni o'rnatmang* —\n"
            f"aks holda Telegram va bank kartangiz *o'g'irlanadi!*\n\n"
            f"⚠️ Никогда не устанавливайте .apk из чатов — это угон аккаунта!\n\n"
            f"🔴 Yuboruvchi *qora ro'yxatga tushdi* va butunlay bloklandi:\n"
            f"👤 {md(username)}  |  🆔 `{uid}`\n"
            f"⛔️ Guruhga *qayta kira olmaydi*."
        )
    elif red:
        # 🔴 Qattiq qoida buzilishi — qizil belgi + butunlay bloklash (qora ro'yxat)
        if "Bot-reklama" in reason:
            violation = (
                "🚫 *Bot-reklama spam* aniqlandi — begona botlar reklama qilindi.\n"
                "Bu reyd-chaqiriq, shuning uchun user *butunlay* bloklandi."
            )
        else:
            violation = (
                "🚫 *Arab/xitoy yozuvi* aniqlandi.\n"
                "Bu qoida buzilishi, shuning uchun user *butunlay* bloklandi."
            )
        body = (
            f"🔴 *QORA RO'YXATGA TUSHDI!* 🔴\n\n"
            f"{violation}\n\n"
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

    # Reyd paytida xabar yuborilmaydi; oddiy holatda faqat eng yangi natija qoladi.
    await send_rotating_action_notice(context, chat.id, body)

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
                logger.warning("Admin signalini yuborib bo'lmadi: admin=%s", admin_id)

    logger.info("Kicked: @%s (id=%s) | %s | %s%s",
                user.username, uid, chat.title, reason, " [HARD-BAN/ЧС]" if hard_ban else "")
    return True


async def warn_first_or_kick(update: Update, context: ContextTypes.DEFAULT_TYPE,
                             reason: str, warning_body=None) -> bool:
    """Birinchi link/video/fayl — ogohlantirish; takrorlansa oddiy kik."""
    chat = update.effective_chat
    user = update.effective_user
    msg = update.effective_message
    if not chat or not user or not msg:
        return False

    warning_key = f"{chat.id}:{user.id}"
    now = time.time()
    warned_at = WARNED_USERS.get(warning_key)
    if warned_at and now - warned_at < WARN_TTL_SECONDS:
        await delete_and_kick(update, context, reason)
        return True

    if not await bot_can_moderate(context, chat.id):
        await send_recruit_message(context, chat.id)
        return True

    try:
        await msg.delete()
    except Exception:
        logger.exception("Birinchi qoidabuzarlik xabarini o'chirib bo'lmadi: chat=%s user=%s", chat.id, user.id)
        return True

    WARNED_USERS[warning_key] = now
    if len(WARNED_USERS) > MAX_WARNED_USERS:
        for old_key, _ in sorted(WARNED_USERS.items(), key=lambda item: item[1])[:5_000]:
            WARNED_USERS.pop(old_key, None)
    save_warned_users(WARNED_USERS)

    display_name = md(user.first_name or "user")
    body = warning_body or (
        f"⚠️ *{display_name}, ogohlantirish!*\n\n"
        f"Guruh qoidalarini buzmang.\n"
        f"Qoidalarga ko'ra hech qanday *link, video va fayl* tashlash mumkin emas.\n\n"
        f"Bu birinchi ogohlantirish. Takrorlansa guruhdan chiqarilasiz!"
    )
    await send_rotating_action_notice(context, chat.id, body)
    logger.info("Warned: @%s (id=%s) | %s | %s", user.username, user.id, chat.title, reason)
    return True


async def warn_sender_chat_or_ban(update: Update, context: ContextTypes.DEFAULT_TYPE,
                                  reason: str) -> bool:
    """Tashqi kanal nomidan spam: birinchi marta warning, takrorida sender-chat ban."""
    chat = update.effective_chat
    msg = update.effective_message
    sender_chat = getattr(msg, "sender_chat", None) if msg else None
    if not chat or not msg or not sender_chat:
        return False

    try:
        await msg.delete()
    except Exception:
        logger.exception("Sender-chat xabarini o'chirib bo'lmadi: chat=%s", chat.id)
        return True

    warning_key = f"{chat.id}:sender:{sender_chat.id}"
    now = time.time()
    warned_at = WARNED_USERS.get(warning_key)
    if warned_at and now - warned_at < WARN_TTL_SECONDS:
        try:
            await context.bot.ban_chat_sender_chat(chat.id, sender_chat.id)
            logger.warning("Sender-chat banned: chat=%s sender=%s reason=%s", chat.id, sender_chat.id, reason)
        except Exception:
            logger.exception("Sender-chat ban bajarilmadi: chat=%s sender=%s", chat.id, sender_chat.id)
        return True

    WARNED_USERS[warning_key] = now
    if len(WARNED_USERS) > MAX_WARNED_USERS:
        for old_key, _ in sorted(WARNED_USERS.items(), key=lambda item: item[1])[:5_000]:
            WARNED_USERS.pop(old_key, None)
    save_warned_users(WARNED_USERS)
    body = (
        f"🙁 *{md(sender_chat.title or 'Kanal')}, reklama tarqatmang!*\n\n"
        f"Bu yer reklama tarqatadigan joy emas.\n"
        f"⚠️ Takrorlansa kanal ushbu guruhda bloklanadi!"
    )
    await send_rotating_action_notice(context, chat.id, body)
    return True

# ──────────────────────────────────────────────
# Antiflood / Slowmode tekshirish
# ──────────────────────────────────────────────

def check_flood(chat_id: int, user_id: int) -> bool:
    now = time.time()
    limit   = SETTINGS.get("flood_limit", 5)
    seconds = SETTINGS.get("flood_seconds", 10)

    users = flood_tracker[chat_id]
    if user_id not in users and len(users) >= 10_000:
        users.pop(next(iter(users)), None)
    msgs = users[user_id]
    msgs = [t for t in msgs if now - t < seconds]
    msgs.append(now)
    users[user_id] = msgs
    return len(msgs) >= limit

def check_slowmode(chat_id: int, user_id: int) -> bool:
    now     = time.time()
    seconds = SETTINGS.get("slowmode_seconds", 60)
    users = slowmode_tracker[chat_id]
    if user_id not in users and len(users) >= 10_000:
        oldest_user = min(users, key=users.get)
        users.pop(oldest_user, None)
    last = users.get(user_id, 0)
    if now - last < seconds:
        return True
    users[user_id] = now
    return False

# ──────────────────────────────────────────────
# Kapcha
# ──────────────────────────────────────────────

async def send_captcha(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, chat_id: int, name: str):
    rng = secrets.SystemRandom()
    a, b   = rng.randint(1, 9), rng.randint(1, 9)
    answer = a + b
    wrong1 = answer + rng.choice([-2, -1, 1, 2])
    wrong2 = answer + rng.choice([-3, 3, -4, 4])

    options = [answer, wrong1, wrong2]
    rng.shuffle(options)

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
                logger.exception("Captcha timeout jazosi bajarilmadi: chat=%s user=%s", chat_id, user_id)

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
                    logger.exception("ЧС userni kirishda bloklab bo'lmadi: chat=%s user=%s", chat_id, member.id)
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

async def lock_chat(context, chat_id: int, auto_unlock_seconds: int = 0):
    """Guruhni muzlatadi va aynan avvalgi ruxsatlarni saqlab qoladi."""
    if chat_id in locked_chats:
        return locked_chats[chat_id].get("generation")
    try:
        chat = await context.bot.get_chat(chat_id)
        original_permissions = getattr(chat, "permissions", None)
        permissions_dict = (
            original_permissions.to_dict()
            if original_permissions is not None
            else OPEN_PERMS.to_dict()
        )
        await context.bot.set_chat_permissions(chat_id, LOCKED_PERMS)
        generation = secrets.token_hex(12)
        locked_chats[chat_id] = {
            "permissions": permissions_dict,
            "generation": generation,
            "locked_at": time.time(),
            "unlock_at": time.time() + auto_unlock_seconds if auto_unlock_seconds > 0 else 0,
        }
        save_locked_chats()
        return generation
    except Exception:
        logger.exception("lock_chat xato: %s", chat_id)
        return False


async def unlock_chat(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> bool:
    """Guruhni ochadi va muzlatishdan oldingi ruxsatlarni tiklaydi."""
    try:
        state = locked_chats.get(chat_id, {})
        saved_permissions = state.get("permissions")
        permissions = (
            ChatPermissions(**saved_permissions)
            if isinstance(saved_permissions, dict)
            else OPEN_PERMS
        )
        await context.bot.set_chat_permissions(chat_id, permissions)
        locked_chats.pop(chat_id, None)
        save_locked_chats()
        return True
    except Exception:
        logger.exception("unlock_chat xato: %s", chat_id)
        return False


async def trigger_raid_lock(context: ContextTypes.DEFAULT_TYPE, chat_id: int, joined: int):
    """Reyd aniqlandi → avto-muzlatish + adminlarga signal + avto-ochish."""
    if not await bot_can_moderate(context, chat_id):
        await send_recruit_message(context, chat_id)   # admin huquqi yo'q — chaqiramiz
        return
    mins = SETTINGS.get("raid_autounlock_min", 10)
    generation = await lock_chat(context, chat_id, mins * 60 if mins else 0)
    if not generation:
        return
    logger.warning("ANTIREYD: chat %s muzlatildi (%s a'zo oqimi)", chat_id, joined)
    try:
        title = (await context.bot.get_chat(chat_id)).title or str(chat_id)
    except Exception:
        title = str(chat_id)
    # Guruhga BITTA qisqa ogohlantirish (flood emas)
    try:
        await context.bot.send_message(
            chat_id,
            "🛡 *Reyd aniqlandi — guruh vaqtincha muzlatildi.*\n"
            "Tez orada avtomatik ochiladi. Adminlar /unlock bilan qo'lda ocha oladi.",
            parse_mode="Markdown",
        )
    except Exception:
        logger.warning("Reyd xabarini guruhga yuborib bo'lmadi: %s", chat_id)
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
            logger.warning("Reyd signalini adminga yuborib bo'lmadi: %s", admin_id)
    # Avto-ochish
    if mins and mins > 0:
        _spawn(auto_unlock_chat(context, chat_id, generation, mins * 60))


async def auto_unlock_chat(context, chat_id: int, generation: str, delay: float):
    """Eski timer yangi lock'ni ochib yubormasligi uchun generation tekshiradi."""
    await asyncio.sleep(max(0, delay))
    state = locked_chats.get(chat_id)
    if not state or state.get("generation") != generation:
        return
    if await unlock_chat(context, chat_id):
        try:
            await context.bot.send_message(chat_id, "✅ Guruh ochildi. Reyd tugadi.")
        except Exception:
            logger.exception("Avto-unlock xabarini yuborib bo'lmadi: %s", chat_id)


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
            logger.debug("Captcha xabari allaqachon o'chgan: chat=%s", chat_id)
    else:
        await query.answer("❌ Noto'g'ri! Siz bot sifatida aniqlangiz.")
        captcha_pending.get(chat_id, {}).pop(user_id, None)
        try:
            await context.bot.ban_chat_member(chat_id, user_id)
            await context.bot.unban_chat_member(chat_id, user_id)
            await query.message.delete()
        except Exception:
            logger.exception("Noto'g'ri captcha jazosi bajarilmadi: chat=%s user=%s", chat_id, user_id)

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
    # Guruhning o'z nomidan yozgan anonim adminni o'tkazamiz. Tashqi kanal
    # nomidan kelgan xabar esa quyidagi moderatsiya pipeline'ida tekshiriladi.
    if msg.sender_chat and msg.sender_chat.id == chat.id:
        return True
    user = update.effective_user
    if not user:
        return False
    if user.id in WHITELIST:
        return True
    if await is_admin_in_chat(update, context):
        return True
    return False

async def moderate_hard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """ЧС, bot-farm va APK tekshiruvi hech qanday soft-exceptiondan o'tmaydi."""
    chat = update.effective_chat
    msg = update.effective_message
    user = update.effective_user
    if not chat or chat.type == "private" or not msg:
        return False

    content = msg.text or msg.caption or ""

    if user and user.id in BLACKLIST:
        await delete_and_kick(
            update, context, "Qora ro'yxatdagi foydalanuvchi", hard_ban=True,
        )
        return True

    if is_bot_promo_spam(content):
        if user:
            BLACKLIST.add(user.id)
            save_blacklist(BLACKLIST)
            await delete_and_kick(
                update, context, "Bot-reklama spam (referal-farm)",
                hard_ban=True, red=True,
            )
        else:
            try:
                await msg.delete()
            except Exception:
                logger.exception("Sender-chat bot reklamasini o'chirib bo'lmadi: %s", chat.id)
        return True

    if await is_apk_file(msg, context):
        if user:
            BLACKLIST.add(user.id)
            save_blacklist(BLACKLIST)
            await delete_and_kick(
                update, context, "APK fayl (xavfli ilova) yuborildi",
                hard_ban=True, red=True,
            )
        else:
            try:
                await msg.delete()
            except Exception:
                logger.exception("Sender-chat APK faylini o'chirib bo'lmadi: %s", chat.id)
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

    # Tashqi kanal nomidan kelgan postda from_user bo'lmaydi: kanalni kik qilib
    # bo'lmaydi, lekin havolali/taqiqlangan xabarning o'zini darhol o'chiramiz.
    if user is None:
        violation = (
            SETTINGS.get("block_links") and message_has_link(msg, content)
        ) or is_advertisement_message(msg, content) or (
            SETTINGS.get("block_arabic") and is_arabic_or_chinese(content)
        ) or contains_keyword(content)
        sender_chat = getattr(msg, "sender_chat", None)
        sender_id = getattr(sender_chat, "id", 0)
        flooded = bool(
            sender_id and SETTINGS.get("antiflood")
            and check_flood(chat_id, sender_id)
        )
        if violation or flooded:
            return await warn_sender_chat_or_ban(
                update, context, "Reklama/flood" if flooded else "Taqiqlangan kontent",
            )
        return False

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
            logger.exception("Slowmode xabarini o'chirib bo'lmadi: chat=%s user=%s", chat_id, user.id)
        return True

    # Arabic/Chinese: global qora ro'yxat + doimiy ban
    if content and SETTINGS.get("block_arabic") and is_arabic_or_chinese(content):
        BLACKLIST.add(user.id)
        save_blacklist(BLACKLIST)
        await delete_and_kick(
            update, context, "Taqiqlangan til (arab/xitoy)",
            hard_ban=True, red=True,
        )
        return True

    # Kanal forward'i, URL-tugmali rasm/video yoki shunga o'xshash reklama.
    if is_advertisement_message(msg, content):
        display_name = md(user.first_name or "user")
        return await warn_first_or_kick(
            update,
            context,
            "Reklama tarqatildi",
            warning_body=(
                f"🙁 *{display_name}, reklama tarqatmang!*\n\n"
                f"Bu yer reklama tarqatadigan joy emas.\n"
                f"Reklama xabaringiz o'chirildi.\n\n"
                f"⚠️ Yana bir marta takrorlansa — guruhdan chiqarilasiz!"
            ),
        )

    # Oddiy URL, yashirilgan TEXT_LINK va inline-tugmadagi havolalar
    if SETTINGS.get("block_links") and message_has_link(msg, content):
        return await warn_first_or_kick(
            update, context, "Xabar ichida havola (link) bor",
        )

    # Kalit so'zlar
    if content and contains_keyword(content):
        await delete_and_kick(update, context, "Taqiqlangan so'z aniqlandi")
        return True

    return False

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if await moderate_hard(update, context):
        return
    if await _should_skip(update, context):
        return
    await moderate(update, context)

async def handle_command_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Komanda ko'rinishidagi spamni CommandHandler'lardan OLDIN tekshiradi."""
    handled = await moderate_hard(update, context)
    if not handled and not await _should_skip(update, context):
        handled = await moderate(update, context)
    if handled:
        raise ApplicationHandlerStop

async def handle_media(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if await moderate_hard(update, context):
        return
    if await _should_skip(update, context):
        return
    msg = update.effective_message

    # Caption ichidagi arab/xitoy yozuvi, link va taqiqlangan so'zlar avval tekshiriladi.
    if await moderate(update, context):
        return

    # Tur bo'yicha qattiq bloklash
    if msg.photo and SETTINGS.get("block_photos"):
        await delete_and_kick(update, context, "Guruhda rasm yuborish taqiqlangan")
        return
    if (msg.video or msg.video_note or msg.animation) and SETTINGS.get("block_videos"):
        if not await warn_first_or_kick(
            update, context, "Guruhda video yuborish taqiqlangan",
        ):
            try:
                await msg.delete()
            except Exception:
                logger.exception("Sender-chat videosini o'chirib bo'lmadi: chat=%s", update.effective_chat.id)
        return
    if msg.document and SETTINGS.get("block_files"):
        if not await warn_first_or_kick(
            update, context, "Guruhda fayl yuborish taqiqlangan",
        ):
            try:
                await msg.delete()
            except Exception:
                logger.exception("Sender-chat faylini o'chirib bo'lmadi: chat=%s", update.effective_chat.id)
        return

    # Qolgan media turlari ruxsat etiladi.

# ──────────────────────────────────────────────
# Komandalar
# ──────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    bot_username = context.bot.username

    if update.effective_chat.type in ("group", "supergroup"):
        if not command_allowed(update, "start"):
            return
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
        sent = await update.message.reply_text(
            text, parse_mode="Markdown", reply_markup=keyboard,
        )
        await replace_last_group_notice(
            context.bot, update.effective_chat.id, sent.message_id,
        )
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
            "`/toggle files` — fayllar\n"
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
    if not command_allowed(update, "info"):
        return
    bot_username = context.bot.username
    text = (
        "🛡 *TezWeb Antispam Bot — Barcha funksiyalar:*\n\n"
        "*🔒 Himoya:*\n"
        "• Havola va @username bloklash\n"
        "• Rasm yuborishni bloklash\n"
        "• Video yuborishni bloklash\n"
        "• Fayl yuborishni bloklash\n"
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
    sent = await update.message.reply_text(
        text, parse_mode="Markdown", reply_markup=keyboard,
    )
    if update.effective_chat.type in ("group", "supergroup"):
        await replace_last_group_notice(
            context.bot, update.effective_chat.id, sent.message_id,
        )


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
        f"{on if s.get('block_files', True) else off} Fayllar bloklash\n"
        f"{on if s.get('antiflood', True) else off} Antiflood\n"
        f"{on if s.get('captcha', False)  else off} Kapcha\n"
        f"{on if s.get('slowmode', False) else off} Sekin rejim ({s.get('slowmode_seconds', 60)} sek)\n"
        f"{on if s.get('block_arabic', False) else off} Arab/xitoy bloklash\n"
        f"{on if s.get('antiraid', True) else off} Antireyd (reyd paytida avto-muzlatish)\n"
        f"🔴 Bot-reklama, APK yoki arab/xitoy yozuvi → avto qora ro'yxat ({len(BLACKLIST)} ta ЧС)\n\n"
        f"*O'zgartirish:* `/toggle links/photos/videos/files/antiflood/captcha/slowmode/arabic/antiraid`\n"
        f"🔒 Qo'lda: guruhda `/lock` (muzlatish) va `/unlock` (ochish)\n"
        f"⛔️ Qora ro'yxat: `/blacklist list` · `/blacklist remove ID`"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def cmd_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private" or not is_super_admin(update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Ishlatish: /toggle links|photos|videos|files|antiflood|captcha|slowmode|arabic|antiraid")
        return

    key_map = {
        "links": "block_links", "photos": "block_photos",
        "videos": "block_videos", "files": "block_files", "antiflood": "antiflood",
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
            msg = await bot.send_message(
                chat_id=chat_id, text=text,
                parse_mode="Markdown", reply_markup=keyboard,
            )
            await replace_last_group_notice(bot, chat_id, msg.message_id)
        except Exception as e:
            logger.error("Promo xato %s: %s", chat_id, e)
        await asyncio.sleep(0.05)


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
            logger.warning("Kunlik hisobot adminga yuborilmadi: %s", admin_id)

    # Barcha guruhlarga yuborish; yangi reklama/natija chiqquncha qoladi.
    bot_username = (await bot.get_me()).username
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Guruhga qo'shish", url=f"https://t.me/{bot_username}?startgroup=true")],
        [InlineKeyboardButton("📢 @tezweb_uz", url="https://t.me/tezweb_uz")],
    ])
    for chat_id in list(GROUPS):
        try:
            msg = await bot.send_message(chat_id=chat_id, text=text, parse_mode="Markdown", reply_markup=keyboard)
            await replace_last_group_notice(bot, chat_id, msg.message_id)
        except Exception as e:
            logger.error("Hisobot xato %s: %s", chat_id, e)
        await asyncio.sleep(0.05)


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
            logger.warning("Haftalik hisobot adminga yuborilmadi: %s", admin_id)


async def cleanup_runtime_state(context: ContextTypes.DEFAULT_TYPE):
    """Eski tracker yozuvlarini tozalab, RAM/disk o'sishini cheklaydi."""
    now = time.time()
    flood_window = SETTINGS.get("flood_seconds", 10)
    for chat_id in list(flood_tracker):
        users = flood_tracker[chat_id]
        for user_id in list(users):
            recent = [stamp for stamp in users[user_id] if now - stamp < flood_window]
            if recent:
                users[user_id] = recent
            else:
                users.pop(user_id, None)
        if not users:
            flood_tracker.pop(chat_id, None)

    slow_ttl = max(SETTINGS.get("slowmode_seconds", 60), 3600)
    for chat_id in list(slowmode_tracker):
        users = slowmode_tracker[chat_id]
        for user_id, stamp in list(users.items()):
            if now - stamp > slow_ttl:
                users.pop(user_id, None)
        if not users:
            slowmode_tracker.pop(chat_id, None)

    join_window = SETTINGS.get("raid_join_window", 30)
    for chat_id in list(join_tracker):
        join_tracker[chat_id] = [stamp for stamp in join_tracker[chat_id] if now - stamp < join_window]
        if not join_tracker[chat_id]:
            join_tracker.pop(chat_id, None)

    for tracker, ttl in (
        (recruit_throttle, 600),
        (notice_throttle, 3600),
        (command_throttle, 300),
    ):
        for key, stamp in list(tracker.items()):
            if now - stamp > ttl:
                tracker.pop(key, None)

    for chat_id, lock in list(_notice_locks.items()):
        if chat_id not in notice_throttle and not lock.locked():
            _notice_locks.pop(chat_id, None)

    expired = [key for key, stamp in WARNED_USERS.items() if now - stamp >= WARN_TTL_SECONDS]
    if expired:
        for key in expired:
            WARNED_USERS.pop(key, None)
        save_warned_users(WARNED_USERS)


async def restore_persisted_locks(application: Application):
    """Restartdan keyin antireyd timerlarini tiklaydi."""
    now = time.time()
    for chat_id, state in list(locked_chats.items()):
        unlock_at = float(state.get("unlock_at", 0) or 0)
        generation = state.get("generation")
        if unlock_at and generation:
            _spawn(auto_unlock_chat(application, chat_id, generation, max(0, unlock_at - now)))


async def job_send_promo(context: ContextTypes.DEFAULT_TYPE):
    await send_promo(context.bot)

async def job_send_daily_report(context: ContextTypes.DEFAULT_TYPE):
    await send_daily_report(context.bot)

async def job_send_weekly_report(context: ContextTypes.DEFAULT_TYPE):
    await send_weekly_report(context.bot)

async def handle_error(update: object, context: ContextTypes.DEFAULT_TYPE):
    error = context.error
    logger.error(
        "Telegram update xatosi: update=%r", update,
        exc_info=(type(error), error, error.__traceback__) if error else None,
    )


# ──────────────────────────────────────────────
# Ishga tushirish
# ──────────────────────────────────────────────

def main() -> None:
    if not BOT_TOKEN:
        print("BOT_TOKEN ni Railway Variables ga kiriting")
        return

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .rate_limiter(AIORateLimiter())
        .post_init(restore_persisted_locks)
        .build()
    )
    app.add_error_handler(handle_error)

    # Komanda matnini oddiy CommandHandler'lardan avval antispamdan o'tkazamiz.
    app.add_handler(MessageHandler(filters.COMMAND, handle_command_text), group=-1)

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
    jq.run_daily(job_send_promo,
                 time=dt.time(2, 0, 0))    # 7:00 Toshkent
    jq.run_daily(job_send_promo,
                 time=dt.time(16, 0, 0))   # 21:00 Toshkent
    jq.run_daily(job_send_daily_report,
                 time=dt.time(17, 0, 0))   # 22:00 Toshkent
    jq.run_daily(job_send_weekly_report,
                 time=dt.time(18, 0, 0),   # 23:00 Toshkent
                 days=(6,))                # 6 = Yakshanba
    jq.run_repeating(cleanup_runtime_state, interval=600, first=600)

    logger.info("✅ TezWeb Antispam Bot ishga tushdi!")
    app.run_polling(allowed_updates=["message", "edited_message", "callback_query"])


if __name__ == "__main__":
    main()

