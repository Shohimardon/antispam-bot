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
ACTION_NOTICES_FILE = str(DATA_DIR / "action_notices.json")
WARNED_USERS_FILE = str(DATA_DIR / "warned_users.json")

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
