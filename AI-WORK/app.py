import os
import sys
import json
import time
import hmac
import html
import uuid
import hashlib
import sqlite3
import logging
import threading
from urllib.parse import parse_qsl

from flask import Flask, jsonify, request, Response
from telebot import TeleBot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo
from dotenv import load_dotenv


# ============================================================
# AI WORK REWARD BOT + TELEGRAM MINI APP
# Single-file version: app.py
# ============================================================

load_dotenv()

# -----------------------------
# Configuration
# -----------------------------
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
WEBAPP_URL = os.getenv("WEBAPP_URL", "").strip()
ADSGRAM_BLOCK_ID = os.getenv("ADSGRAM_BLOCK_ID", "").strip()
ADSGRAM_REWARD_SECRET = os.getenv("ADSGRAM_REWARD_SECRET", "").strip()
DATABASE_PATH = os.getenv("DATABASE_PATH", "reward.db").strip()

HOST = os.getenv("HOST", "0.0.0.0").strip()
PORT = int(os.getenv("PORT", "8080"))
AUTH_MAX_AGE = int(os.getenv("AUTH_MAX_AGE", "86400"))
AD_SESSION_TIMEOUT = int(os.getenv("AD_SESSION_TIMEOUT", "1800"))
AD_COOLDOWN_SECONDS = int(os.getenv("AD_COOLDOWN_SECONDS", "10"))
WITHDRAW_MINIMUM = 100
REWARD_EVERY_ADS = 10
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN .env faylida berilmagan.")

if not WEBAPP_URL:
    raise RuntimeError("WEBAPP_URL .env faylida berilmagan.")

if not ADSGRAM_BLOCK_ID:
    raise RuntimeError("ADSGRAM_BLOCK_ID .env faylida berilmagan.")

if not ADSGRAM_REWARD_SECRET:
    raise RuntimeError("ADSGRAM_REWARD_SECRET .env faylida berilmagan.")

if not ADSGRAM_REWARD_SECRET.isalnum() or len(ADSGRAM_REWARD_SECRET) < 32:
    raise RuntimeError(
        "ADSGRAM_REWARD_SECRET kamida 32 ta harf/raqamdan iborat bo'lishi kerak."
    )


# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("reward-app")


# -----------------------------
# Flask + Telegram Bot
# -----------------------------
app = Flask(__name__)
bot = TeleBot(BOT_TOKEN, parse_mode="HTML")


# ============================================================
# DATABASE
# ============================================================

DB_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER NOT NULL UNIQUE,
    username TEXT,
    first_name TEXT,
    last_name TEXT,
    balance_points INTEGER NOT NULL DEFAULT 0,
    total_ads INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ad_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL UNIQUE,
    telegram_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    adsgram_confirmed_at INTEGER,
    rewarded_at INTEGER,
    FOREIGN KEY (telegram_id) REFERENCES users(telegram_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS withdrawals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    processed_at INTEGER,
    FOREIGN KEY (telegram_id) REFERENCES users(telegram_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ad_views_telegram_id
ON ad_views(telegram_id);

CREATE INDEX IF NOT EXISTS idx_ad_views_status
ON ad_views(status);

CREATE INDEX IF NOT EXISTS idx_withdrawals_telegram_id
ON withdrawals(telegram_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_ad_per_user
ON ad_views(telegram_id)
WHERE status IN ('pending', 'adsgram_confirmed');

CREATE INDEX IF NOT EXISTS idx_users_updated_at
ON users(updated_at);
"""


def db_connect():
    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
        isolation_level=None,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db():
    conn = db_connect()
    try:
        conn.executescript(DB_SCHEMA)
    finally:
        conn.close()


def now_ts():
    return int(time.time())


def get_user(telegram_id):
    conn = db_connect()
    try:
        return conn.execute(
            """
            SELECT *
            FROM users
            WHERE telegram_id = ?
            """,
            (telegram_id,),
        ).fetchone()
    finally:
        conn.close()


def upsert_user(
    telegram_id,
    username=None,
    first_name=None,
    last_name=None,
):
    timestamp = now_ts()

    conn = db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")

        existing = conn.execute(
            """
            SELECT id
            FROM users
            WHERE telegram_id = ?
            """,
            (telegram_id,),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE users
                SET username = COALESCE(?, username),
                    first_name = COALESCE(?, first_name),
                    last_name = COALESCE(?, last_name),
                    updated_at = ?
                WHERE telegram_id = ?
                """,
                (
                    username,
                    first_name,
                    last_name,
                    timestamp,
                    telegram_id,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO users (
                    telegram_id,
                    username,
                    first_name,
                    last_name,
                    balance_points,
                    total_ads,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, 0, 0, ?, ?)
                """,
                (
                    telegram_id,
                    username,
                    first_name,
                    last_name,
                    timestamp,
                    timestamp,
                ),
            )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# TELEGRAM WEB APP AUTH
# ============================================================

def validate_telegram_init_data(init_data):
    """
    Validates Telegram WebApp initData using the official HMAC-SHA-256 scheme.

    Returns:
        Telegram user dict on success.

    Raises:
        ValueError on invalid/expired data.
    """
    if not init_data:
        raise ValueError("Telegram initData yuborilmadi.")

    try:
        pairs = parse_qsl(
            init_data,
            keep_blank_values=True,
            strict_parsing=True,
        )
    except ValueError as exc:
        raise ValueError("Telegram initData formati noto'g'ri.") from exc

    data = dict(pairs)

    received_hash = data.pop("hash", None)
    if not received_hash:
        raise ValueError("Telegram initData hash topilmadi.")

    auth_date_raw = data.get("auth_date")
    if not auth_date_raw:
        raise ValueError("auth_date topilmadi.")

    try:
        auth_date = int(auth_date_raw)
    except ValueError as exc:
        raise ValueError("auth_date noto'g'ri.") from exc

    if abs(now_ts() - auth_date) > AUTH_MAX_AGE:
        raise ValueError("Telegram sessiyasi eskirgan. Mini App'ni qayta oching.")

    data_check_string = "\n".join(
        f"{key}={value}"
        for key, value in sorted(data.items())
    )

    secret_key = hmac.new(
        b"WebAppData",
        BOT_TOKEN.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    calculated_hash = hmac.new(
        secret_key,
        data_check_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        raise ValueError("Telegram initData imzosi noto'g'ri.")

    user_raw = data.get("user")
    if not user_raw:
        raise ValueError("Telegram user ma'lumoti topilmadi.")

    try:
        user = json.loads(user_raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Telegram user JSON noto'g'ri.") from exc

    telegram_id = user.get("id")
    if not isinstance(telegram_id, int):
        raise ValueError("Telegram user ID noto'g'ri.")

    return user


def authenticated_user():
    """
    Reads Telegram initData from:
        X-Telegram-Init-Data

    The frontend user_id is NEVER trusted.
    """
    init_data = request.headers.get("X-Telegram-Init-Data", "").strip()
    user = validate_telegram_init_data(init_data)

    telegram_id = int(user["id"])

    upsert_user(
        telegram_id=telegram_id,
        username=user.get("username"),
        first_name=user.get("first_name"),
        last_name=user.get("last_name"),
    )

    return user


# ============================================================
# JSON HELPERS
# ============================================================

def success(data=None, message="OK"):
    return jsonify(
        {
            "ok": True,
            "message": message,
            "data": data or {},
        }
    )


def error_response(code, message, status=400):
    return (
        jsonify(
            {
                "ok": False,
                "error": {
                    "code": code,
                    "message": message,
                },
            }
        ),
        status,
    )


def user_stats(telegram_id):
    user = get_user(telegram_id)

    if not user:
        raise ValueError("Foydalanuvchi topilmadi.")

    total_ads = int(user["total_ads"])
    earned_stars = total_ads // REWARD_EVERY_ADS
    progress_ads = total_ads % REWARD_EVERY_ADS

    return {
        "telegram_id": int(user["telegram_id"]),
        "username": user["username"],
        "first_name": user["first_name"],
        "balance": int(user["balance_points"]),
        "total_ads": total_ads,
        "earned_stars": earned_stars,
        "progress_ads": progress_ads,
        "reward_every": REWARD_EVERY_ADS,
        "withdraw_minimum": WITHDRAW_MINIMUM,
    }


# ============================================================
# AD SESSION SERVICE
# ============================================================

def create_ad_session(telegram_id):
    timestamp = now_ts()

    conn = db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")

        # Expire only very old unfinished sessions.
        # This prevents users from getting permanently stuck.
        # AdsGram Reward URL is expected to arrive shortly after a
        # completed rewarded ad.
        conn.execute(
            """
            UPDATE ad_views
            SET status = 'expired'
            WHERE telegram_id = ?
              AND status = 'pending'
              AND created_at < ?
            """,
            (
                telegram_id,
                timestamp - AD_SESSION_TIMEOUT,
            ),
        )

        recent = conn.execute(
            """
            SELECT session_id, status, created_at
            FROM ad_views
            WHERE telegram_id = ?
              AND status IN ('pending', 'adsgram_confirmed')
            ORDER BY id DESC
            LIMIT 1
            """,
            (telegram_id,),
        ).fetchone()

        if recent:
            conn.rollback()
            return None, "ACTIVE_SESSION"

        last_rewarded = conn.execute(
            """
            SELECT rewarded_at
            FROM ad_views
            WHERE telegram_id = ?
              AND status = 'rewarded'
              AND rewarded_at IS NOT NULL
            ORDER BY rewarded_at DESC
            LIMIT 1
            """,
            (telegram_id,),
        ).fetchone()

        if last_rewarded:
            elapsed = timestamp - int(last_rewarded["rewarded_at"])
            if elapsed < AD_COOLDOWN_SECONDS:
                conn.rollback()
                return None, "COOLDOWN"

        session_id = str(uuid.uuid4())

        conn.execute(
            """
            INSERT INTO ad_views (
                session_id,
                telegram_id,
                status,
                created_at
            )
            VALUES (?, ?, 'pending', ?)
            """,
            (
                session_id,
                telegram_id,
                timestamp,
            ),
        )

        conn.commit()
        return session_id, None

    except sqlite3.IntegrityError:
        conn.rollback()
        return None, "ACTIVE_SESSION"
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def mark_adsgram_confirmed(telegram_id):
    """
    AdsGram Reward URL gives us the Telegram user ID.

    We intentionally match only the user's single active ad session.
    Parallel ad sessions are prohibited by the database unique index.
    """
    timestamp = now_ts()

    conn = db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")

        session = conn.execute(
            """
            SELECT id, session_id, status, created_at
            FROM ad_views
            WHERE telegram_id = ?
              AND status = 'pending'
            ORDER BY id DESC
            LIMIT 1
            """,
            (telegram_id,),
        ).fetchone()

        if not session:
            conn.rollback()
            return False, "NO_PENDING_SESSION"

        if timestamp - int(session["created_at"]) > AD_SESSION_TIMEOUT:
            conn.execute(
                """
                UPDATE ad_views
                SET status = 'expired'
                WHERE id = ?
                """,
                (session["id"],),
            )
            conn.commit()
            return False, "SESSION_EXPIRED"

        conn.execute(
            """
            UPDATE ad_views
            SET status = 'adsgram_confirmed',
                adsgram_confirmed_at = ?
            WHERE id = ?
              AND status = 'pending'
            """,
            (
                timestamp,
                session["id"],
            ),
        )

        conn.commit()
        return True, session["session_id"]

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def finalize_reward(telegram_id, session_id):
    """
    Reward is granted ONLY after:
      1. AdsGram server-side callback has marked the session
         adsgram_confirmed.
      2. The frontend sends the session_id after AdsGram show()
         successfully resolves.

    This makes the database the source of truth.
    """
    timestamp = now_ts()

    conn = db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")

        session = conn.execute(
            """
            SELECT id, status, telegram_id
            FROM ad_views
            WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()

        if not session:
            conn.rollback()
            return {
                "ok": False,
                "code": "SESSION_NOT_FOUND",
            }

        if int(session["telegram_id"]) != int(telegram_id):
            conn.rollback()
            return {
                "ok": False,
                "code": "SESSION_USER_MISMATCH",
            }

        if session["status"] == "rewarded":
            user = conn.execute(
                """
                SELECT balance_points, total_ads
                FROM users
                WHERE telegram_id = ?
                """,
                (telegram_id,),
            ).fetchone()

            conn.rollback()

            return {
                "ok": True,
                "already_rewarded": True,
                "balance": int(user["balance_points"]),
                "total_ads": int(user["total_ads"]),
            }

        if session["status"] != "adsgram_confirmed":
            conn.rollback()
            return {
                "ok": False,
                "code": "ADS_NOT_CONFIRMED",
            }

        user = conn.execute(
            """
            SELECT balance_points, total_ads
            FROM users
            WHERE telegram_id = ?
            """,
            (telegram_id,),
        ).fetchone()

        if not user:
            conn.rollback()
            return {
                "ok": False,
                "code": "USER_NOT_FOUND",
            }

        old_total_ads = int(user["total_ads"])
        new_total_ads = old_total_ads + 1

        old_balance = int(user["balance_points"])
        reward_added = 1 if new_total_ads % REWARD_EVERY_ADS == 0 else 0
        new_balance = old_balance + reward_added

        conn.execute(
            """
            UPDATE users
            SET total_ads = ?,
                balance_points = ?,
                updated_at = ?
            WHERE telegram_id = ?
            """,
            (
                new_total_ads,
                new_balance,
                timestamp,
                telegram_id,
            ),
        )

        conn.execute(
            """
            UPDATE ad_views
            SET status = 'rewarded',
                rewarded_at = ?
            WHERE session_id = ?
              AND status = 'adsgram_confirmed'
            """,
            (
                timestamp,
                session_id,
            ),
        )

        conn.commit()

        return {
            "ok": True,
            "already_rewarded": False,
            "reward_added": reward_added,
            "balance": new_balance,
            "total_ads": new_total_ads,
            "progress_ads": new_total_ads % REWARD_EVERY_ADS,
        }

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# WITHDRAWAL SERVICE
# ============================================================

def create_withdrawal(telegram_id, amount):
    if not isinstance(amount, int):
        return {
            "ok": False,
            "code": "INVALID_AMOUNT",
            "message": "Miqdor butun son bo'lishi kerak.",
        }

    if amount < WITHDRAW_MINIMUM:
        return {
            "ok": False,
            "code": "MINIMUM_NOT_REACHED",
            "message": f"Minimal chiqarish miqdori {WITHDRAW_MINIMUM} ⭐",
        }

    if amount <= 0:
        return {
            "ok": False,
            "code": "INVALID_AMOUNT",
            "message": "Miqdor 0 dan katta bo'lishi kerak.",
        }

    timestamp = now_ts()

    conn = db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")

        user = conn.execute(
            """
            SELECT balance_points
            FROM users
            WHERE telegram_id = ?
            """,
            (telegram_id,),
        ).fetchone()

        if not user:
            conn.rollback()
            return {
                "ok": False,
                "code": "USER_NOT_FOUND",
                "message": "Foydalanuvchi topilmadi.",
            }

        pending = conn.execute(
            """
            SELECT id
            FROM withdrawals
            WHERE telegram_id = ?
              AND status = 'pending'
            LIMIT 1
            """,
            (telegram_id,),
        ).fetchone()

        if pending:
            conn.rollback()
            return {
                "ok": False,
                "code": "PENDING_WITHDRAWAL",
                "message": "Sizda allaqachon ko'rib chiqilayotgan withdrawal bor.",
            }

        balance = int(user["balance_points"])

        if amount > balance:
            conn.rollback()
            return {
                "ok": False,
                "code": "INSUFFICIENT_BALANCE",
                "message": "Balansingiz yetarli emas.",
            }

        conn.execute(
            """
            UPDATE users
            SET balance_points = balance_points - ?,
                updated_at = ?
            WHERE telegram_id = ?
            """,
            (
                amount,
                timestamp,
                telegram_id,
            ),
        )

        cursor = conn.execute(
            """
            INSERT INTO withdrawals (
                telegram_id,
                amount,
                status,
                created_at
            )
            VALUES (?, ?, 'pending', ?)
            """,
            (
                telegram_id,
                amount,
                timestamp,
            ),
        )

        withdrawal_id = cursor.lastrowid

        conn.commit()

        return {
            "ok": True,
            "withdrawal_id": withdrawal_id,
            "amount": amount,
            "remaining_balance": balance - amount,
            "status": "pending",
        }

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ============================================================
# WEB APP HTML
# ============================================================

def render_webapp():
    # json.dumps safely injects only the public block ID.
    public_config = json.dumps(
        {
            "adsgramBlockId": ADSGRAM_BLOCK_ID,
        },
        ensure_ascii=False,
    )

    page = r"""<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"
    >
    <meta name="theme-color" content="#0f172a">
    <title>Reward Mini App</title>

    <script src="https://telegram.org/js/telegram-web-app.js"></script>
    <script src="https://sad.adsgram.ai/js/sad.min.js"></script>

    <style>
        :root {
            color-scheme: light dark;
            --bg: var(--tg-theme-bg-color, #0f172a);
            --secondary-bg: var(--tg-theme-secondary-bg-color, #172033);
            --text: var(--tg-theme-text-color, #ffffff);
            --hint: var(--tg-theme-hint-color, #9ca3af);
            --button: var(--tg-theme-button-color, #2481cc);
            --button-text: var(--tg-theme-button-text-color, #ffffff);
            --danger: #ef4444;
            --success: #22c55e;
            --border: rgba(127, 127, 127, 0.20);
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            background: var(--bg);
            color: var(--text);
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                Roboto,
                Arial,
                sans-serif;
        }

        .container {
            width: min(100%, 520px);
            margin: 0 auto;
            padding: 18px;
        }

        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 18px;
        }

        .brand {
            font-size: 22px;
            font-weight: 800;
        }

        .user-name {
            max-width: 220px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: var(--hint);
            font-size: 14px;
        }

        .card {
            background: var(--secondary-bg);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 20px;
            margin-bottom: 14px;
        }

        .balance-label {
            color: var(--hint);
            font-size: 14px;
            margin-bottom: 5px;
        }

        .balance {
            font-size: 42px;
            line-height: 1.1;
            font-weight: 900;
        }

        .stats {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
        }

        .stat {
            padding: 14px;
            border: 1px solid var(--border);
            border-radius: 16px;
        }

        .stat-value {
            font-size: 24px;
            font-weight: 800;
        }

        .stat-label {
            color: var(--hint);
            font-size: 12px;
            margin-top: 4px;
        }

        button {
            width: 100%;
            border: 0;
            border-radius: 16px;
            padding: 15px 18px;
            font-size: 16px;
            font-weight: 800;
            cursor: pointer;
            background: var(--button);
            color: var(--button-text);
        }

        button:disabled {
            opacity: 0.55;
            cursor: not-allowed;
        }

        .secondary-button {
            margin-top: 10px;
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text);
        }

        .message {
            min-height: 22px;
            margin: 10px 0 0;
            color: var(--hint);
            font-size: 14px;
            line-height: 1.45;
        }

        .message.success {
            color: var(--success);
        }

        .message.error {
            color: var(--danger);
        }

        .progress-wrap {
            margin-top: 16px;
        }

        .progress-top {
            display: flex;
            justify-content: space-between;
            color: var(--hint);
            font-size: 12px;
            margin-bottom: 7px;
        }

        .progress {
            width: 100%;
            height: 9px;
            overflow: hidden;
            border-radius: 99px;
            background: rgba(127, 127, 127, 0.18);
        }

        .progress-bar {
            height: 100%;
            width: 0%;
            border-radius: inherit;
            background: var(--button);
            transition: width 0.25s ease;
        }

        .withdraw-row {
            display: flex;
            gap: 10px;
        }

        input {
            width: 100%;
            min-width: 0;
            padding: 14px;
            border: 1px solid var(--border);
            border-radius: 14px;
            outline: none;
            background: transparent;
            color: var(--text);
            font-size: 16px;
        }

        .withdraw-row button {
            width: 130px;
            flex: 0 0 130px;
        }

        .footer {
            text-align: center;
            color: var(--hint);
            font-size: 12px;
            padding: 8px 0 22px;
        }

        .loading {
            opacity: 0.7;
        }

        @media (max-width: 380px) {
            .container {
                padding: 12px;
            }

            .withdraw-row {
                flex-direction: column;
            }

            .withdraw-row button {
                width: 100%;
                flex-basis: auto;
            }
        }
    </style>
</head>

<body>
<div class="container">
    <div class="header">
        <div>
            <div class="brand">⭐ Reward</div>
            <div id="userName" class="user-name">Telegram user</div>
        </div>
    </div>

    <div class="card">
        <div class="balance-label">Balans</div>
        <div id="balance" class="balance">0 ⭐</div>

        <div class="stats">
            <div class="stat">
                <div id="totalAds" class="stat-value">0</div>
                <div class="stat-label">Ko‘rilgan reklamalar</div>
            </div>

            <div class="stat">
                <div id="earnedStars" class="stat-value">0 ⭐</div>
                <div class="stat-label">Jami earned stars</div>
            </div>
        </div>

        <div class="progress-wrap">
            <div class="progress-top">
                <span>Keyingi ⭐ uchun progress</span>
                <span id="progressText">0 / 10</span>
            </div>

            <div class="progress">
                <div id="progressBar" class="progress-bar"></div>
            </div>
        </div>
    </div>

    <div class="card">
        <button id="watchButton">
            🎬 Reklama ko‘rish
        </button>

        <div id="message" class="message"></div>
    </div>

    <div class="card">
        <div class="balance-label">
            Withdrawal minimum: 100 ⭐
        </div>

        <div class="withdraw-row">
            <input
                id="withdrawAmount"
                type="number"
                min="100"
                step="1"
                placeholder="Miqdor"
            >

            <button id="withdrawButton">
                Chiqarish
            </button>
        </div>

        <div id="withdrawMessage" class="message"></div>
    </div>

    <div class="footer">
        Reward faqat AdsGram tomonidan tasdiqlangan muvaffaqiyatli reklama uchun beriladi.
    </div>
</div>

<script>
    const APP_CONFIG = __APP_CONFIG__;

    const tg = window.Telegram?.WebApp;

    if (tg) {
        tg.ready();
        tg.expand();
    }

    const watchButton = document.getElementById("watchButton");
    const withdrawButton = document.getElementById("withdrawButton");

    const balanceEl = document.getElementById("balance");
    const totalAdsEl = document.getElementById("totalAds");
    const earnedStarsEl = document.getElementById("earnedStars");
    const progressTextEl = document.getElementById("progressText");
    const progressBarEl = document.getElementById("progressBar");
    const userNameEl = document.getElementById("userName");
    const messageEl = document.getElementById("message");
    const withdrawMessageEl = document.getElementById("withdrawMessage");
    const withdrawAmountEl = document.getElementById("withdrawAmount");

    let adController = null;
    let adShowing = false;

    function getInitData() {
        return tg?.initData || "";
    }

    async function api(path, options = {}) {
        const headers = {
            "Content-Type": "application/json",
            "X-Telegram-Init-Data": getInitData(),
            ...(options.headers || {})
        };

        const response = await fetch(path, {
            ...options,
            headers
        });

        let data;

        try {
            data = await response.json();
        } catch {
            throw new Error("Server noto‘g‘ri javob qaytardi.");
        }

        if (!response.ok || !data.ok) {
            const msg =
                data?.error?.message ||
                data?.message ||
                "Noma’lum server xatosi.";

            const error = new Error(msg);
            error.payload = data;
            throw error;
        }

        return data;
    }

    function setMessage(text, type = "") {
        messageEl.textContent = text;
        messageEl.className = "message " + type;
    }

    function setWithdrawMessage(text, type = "") {
        withdrawMessageEl.textContent = text;
        withdrawMessageEl.className = "message " + type;
    }

    function renderStats(stats) {
        balanceEl.textContent = `${stats.balance} ⭐`;
        totalAdsEl.textContent = String(stats.total_ads);
        earnedStarsEl.textContent = `${stats.earned_stars} ⭐`;

        progressTextEl.textContent =
            `${stats.progress_ads} / ${stats.reward_every}`;

        const percent =
            (stats.progress_ads / stats.reward_every) * 100;

        progressBarEl.style.width = `${percent}%`;

        if (stats.first_name || stats.username) {
            userNameEl.textContent =
                stats.first_name ||
                stats.username ||
                "Telegram user";
        }
    }

    async function loadBalance() {
        if (!getInitData()) {
            setMessage(
                "Mini App’ni Telegram ichidan oching.",
                "error"
            );
            watchButton.disabled = true;
            withdrawButton.disabled = true;
            return;
        }

        try {
            const result = await api("/api/balance");
            renderStats(result.data);
        } catch (error) {
            setMessage(error.message, "error");
        }
    }

    async function waitForReward(sessionId, attempts = 8) {
        for (let i = 0; i < attempts; i++) {
            try {
                const result = await api("/api/ad-completed", {
                    method: "POST",
                    body: JSON.stringify({
                        session_id: sessionId
                    })
                });

                return result;
            } catch (error) {
                const code = error.payload?.error?.code;

                if (
                    code !== "ADS_NOT_CONFIRMED" &&
                    code !== "SESSION_NOT_FOUND"
                ) {
                    throw error;
                }

                await new Promise(
                    resolve => setTimeout(resolve, 1500)
                );
            }
        }

        throw new Error(
            "AdsGram server tasdig‘i hali kelmadi. Bir necha soniyadan keyin balansni yangilang."
        );
    }

    async function showRewardAd() {
        if (adShowing) {
            return;
        }

        if (!getInitData()) {
            setMessage(
                "Mini App’ni Telegram ichidan oching.",
                "error"
            );
            return;
        }

        if (!window.Adsgram) {
            setMessage(
                "AdsGram SDK yuklanmadi. Internetni tekshiring.",
                "error"
            );
            return;
        }

        adShowing = true;
        watchButton.disabled = true;
        watchButton.textContent = "⏳ Reklama tayyorlanmoqda...";
        setMessage("");

        let sessionId = null;

        try {
            const sessionResult = await api("/api/ad-session", {
                method: "POST"
            });

            sessionId = sessionResult.data.session_id;

            if (!adController) {
                adController = window.Adsgram.init({
                    blockId: APP_CONFIG.adsgramBlockId
                });
            }

            if (!adController) {
                throw new Error("AdsGram controller yaratilmadi.");
            }

            watchButton.textContent = "📺 Reklama ko‘rsatilmoqda...";

            const result = await adController.show();

            /*
             * AdsGram Rewarded format:
             * show() resolves when the rewarded ad is watched
             * to the end. We still DO NOT grant reward here.
             * The backend waits for AdsGram Reward URL confirmation.
             */
            if (!result || result.done === false) {
                throw new Error(
                    "Reklama muvaffaqiyatli yakunlanmadi."
                );
            }

            setMessage(
                "Reklama yakunlandi. Server tasdig‘i kutilmoqda..."
            );

            const rewardResult =
                await waitForReward(sessionId);

            renderStats({
                ...rewardResult.data,
                first_name: undefined,
                username: undefined
            });

            if (rewardResult.data.reward_added > 0) {
                setMessage(
                    "🎉 10 ta tasdiqlangan reklama uchun 1 ⭐ qo‘shildi!",
                    "success"
                );
            } else {
                setMessage(
                    "✅ Reklama tasdiqlandi. Progress yangilandi.",
                    "success"
                );
            }
        } catch (error) {
            console.error(error);

            setMessage(
                error.message || "Reklama jarayonida xatolik.",
                "error"
            );
        } finally {
            adShowing = false;
            watchButton.disabled = false;
            watchButton.textContent = "🎬 Reklama ko‘rish";
            await loadBalance();
        }
    }

    async function withdraw() {
        if (adShowing) {
            setWithdrawMessage(
                "Avval reklama jarayoni tugashini kuting.",
                "error"
            );
            return;
        }

        const amount = Number(withdrawAmountEl.value);

        if (!Number.isInteger(amount) || amount <= 0) {
            setWithdrawMessage(
                "Miqdorni butun son ko‘rinishida kiriting.",
                "error"
            );
            return;
        }

        withdrawButton.disabled = true;
        setWithdrawMessage("So‘rov yuborilmoqda...");

        try {
            const result = await api("/api/withdraw", {
                method: "POST",
                body: JSON.stringify({
                    amount
                })
            });

            withdrawAmountEl.value = "";

            setWithdrawMessage(
                `So‘rov qabul qilindi. ID: ${result.data.withdrawal_id}`,
                "success"
            );

            await loadBalance();
        } catch (error) {
            setWithdrawMessage(
                error.message,
                "error"
            );
        } finally {
            withdrawButton.disabled = false;
        }
    }

    watchButton.addEventListener(
        "click",
        showRewardAd
    );

    withdrawButton.addEventListener(
        "click",
        withdraw
    );

    loadBalance();
</script>
</body>
</html>"""

    return page.replace(
        "__APP_CONFIG__",
        public_config,
    )


# ============================================================
# CORS / SECURITY HEADERS
# ============================================================

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    origin = request.headers.get("Origin")

    if origin and origin.rstrip("/") == WEBAPP_URL.rstrip("/"):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, X-Telegram-Init-Data"
        )
        response.headers["Access-Control-Allow-Methods"] = (
            "GET, POST, OPTIONS"
        )

    return response


@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        return Response(status=204)


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def home():
    return Response(
        render_webapp(),
        mimetype="text/html",
    )


@app.get("/health")
def health():
    return success(
        {
            "service": "reward-mini-app",
            "status": "ok",
        }
    )


@app.get("/api/balance")
def api_balance():
    try:
        user = authenticated_user()
        stats = user_stats(int(user["id"]))
        return success(stats)

    except ValueError as exc:
        return error_response(
            "AUTH_ERROR",
            str(exc),
            401,
        )
    except Exception:
        logger.exception("Balance error")
        return error_response(
            "SERVER_ERROR",
            "Server xatosi.",
            500,
        )


@app.post("/api/ad-session")
def api_ad_session():
    try:
        user = authenticated_user()
        telegram_id = int(user["id"])

        session_id, reason = create_ad_session(
            telegram_id
        )

        if reason == "ACTIVE_SESSION":
            return error_response(
                "ACTIVE_SESSION",
                "Sizda allaqachon reklama sessiyasi bor. Avval uning tugashini kuting.",
                409,
            )

        if reason == "COOLDOWN":
            return error_response(
                "COOLDOWN",
                "Iltimos, keyingi reklamadan oldin biroz kuting.",
                429,
            )

        if not session_id:
            return error_response(
                "SESSION_CREATE_FAILED",
                "Reklama sessiyasini yaratib bo'lmadi.",
                500,
            )

        return success(
            {
                "session_id": session_id,
            },
            "Ad session yaratildi.",
        )

    except ValueError as exc:
        return error_response(
            "AUTH_ERROR",
            str(exc),
            401,
        )
    except Exception:
        logger.exception("Ad session error")
        return error_response(
            "SERVER_ERROR",
            "Server xatosi.",
            500,
        )


@app.post("/api/ad-completed")
def api_ad_completed():
    try:
        user = authenticated_user()
        telegram_id = int(user["id"])

        payload = request.get_json(
            silent=True
        ) or {}

        session_id = str(
            payload.get("session_id", "")
        ).strip()

        if not session_id:
            return error_response(
                "SESSION_ID_REQUIRED",
                "session_id kerak.",
                400,
            )

        if len(session_id) > 100:
            return error_response(
                "INVALID_SESSION_ID",
                "session_id noto'g'ri.",
                400,
            )

        result = finalize_reward(
            telegram_id,
            session_id,
        )

        if not result["ok"]:
            code = result["code"]

            if code == "ADS_NOT_CONFIRMED":
                return error_response(
                    code,
                    "AdsGram server tasdig‘i hali kelmadi.",
                    409,
                )

            if code == "SESSION_NOT_FOUND":
                return error_response(
                    code,
                    "Reklama sessiyasi topilmadi.",
                    404,
                )

            if code == "SESSION_USER_MISMATCH":
                return error_response(
                    code,
                    "Reklama sessiyasi foydalanuvchiga tegishli emas.",
                    403,
                )

            return error_response(
                code,
                "Reward berilmadi.",
                400,
            )

        return success(
            {
                "balance": result["balance"],
                "total_ads": result["total_ads"],
                "progress_ads": result["progress_ads"],
                "reward_added": result["reward_added"],
                "already_rewarded": result["already_rewarded"],
                "earned_stars": (
                    result["total_ads"] // REWARD_EVERY_ADS
                ),
                "reward_every": REWARD_EVERY_ADS,
                "withdraw_minimum": WITHDRAW_MINIMUM,
            },
            "Reward muvaffaqiyatli qayta ishlandi.",
        )

    except ValueError as exc:
        return error_response(
            "AUTH_ERROR",
            str(exc),
            401,
        )
    except Exception:
        logger.exception("Ad completed error")
        return error_response(
            "SERVER_ERROR",
            "Server xatosi.",
            500,
        )


@app.post("/api/withdraw")
def api_withdraw():
    try:
        user = authenticated_user()
        telegram_id = int(user["id"])

        payload = request.get_json(
            silent=True
        ) or {}

        amount_raw = payload.get("amount")

        # JSON bool is technically an int subclass in Python.
        if isinstance(amount_raw, bool):
            return error_response(
                "INVALID_AMOUNT",
                "Miqdor noto'g'ri.",
                400,
            )

        try:
            amount = int(amount_raw)
        except (TypeError, ValueError):
            return error_response(
                "INVALID_AMOUNT",
                "Miqdor butun son bo'lishi kerak.",
                400,
            )

        result = create_withdrawal(
            telegram_id,
            amount,
        )

        if not result["ok"]:
            status = 400

            if result["code"] == "PENDING_WITHDRAWAL":
                status = 409

            return error_response(
                result["code"],
                result["message"],
                status,
            )

        return success(
            {
                "withdrawal_id": result["withdrawal_id"],
                "amount": result["amount"],
                "remaining_balance": result["remaining_balance"],
                "status": result["status"],
            },
            "Withdrawal so'rovi qabul qilindi.",
        )

    except ValueError as exc:
        return error_response(
            "AUTH_ERROR",
            str(exc),
            401,
        )
    except Exception:
        logger.exception("Withdrawal error")
        return error_response(
            "SERVER_ERROR",
            "Server xatosi.",
            500,
        )


@app.get("/api/adsgram/reward/<secret>")
def adsgram_reward(secret):
    """
    AdsGram server-side Reward URL.

    Configure this in AdsGram as:

    https://YOUR-DOMAIN/api/adsgram/reward/YOUR_SECRET?userid=[userId]

    AdsGram replaces [userId] with the Telegram ID.
    """
    if not hmac.compare_digest(
        secret,
        ADSGRAM_REWARD_SECRET,
    ):
        logger.warning("Invalid AdsGram reward secret.")
        return Response(
            "Forbidden",
            status=403,
        )

    userid = (
        request.args.get("userid")
        or request.args.get("userId")
        or ""
    ).strip()

    if not userid.isdigit():
        return Response(
            "Invalid userid",
            status=400,
        )

    telegram_id = int(userid)

    try:
        upsert_user(telegram_id)

        confirmed, value = mark_adsgram_confirmed(
            telegram_id
        )

        if confirmed:
            logger.info(
                "AdsGram confirmed reward: user=%s session=%s",
                telegram_id,
                value,
            )
            return Response(
                "OK",
                status=200,
            )

        logger.info(
            "AdsGram callback ignored: user=%s reason=%s",
            telegram_id,
            value,
        )

        # A valid AdsGram callback was received, but there was
        # no usable pending session. Return 200 to avoid repeated
        # delivery of the same callback.
        return Response(
            "IGNORED",
            status=200,
        )

    except Exception:
        logger.exception(
            "AdsGram reward callback error"
        )
        return Response(
            "Server error",
            status=500,
        )


# ============================================================
# TELEGRAM BOT
# ============================================================

def main_menu():
    keyboard = InlineKeyboardMarkup()

    keyboard.add(
        InlineKeyboardButton(
            "🎬 Reklama ko‘rish",
            web_app=WebAppInfo(
                url=WEBAPP_URL
            ),
        )
    )

    keyboard.add(
        InlineKeyboardButton(
            "⭐ Balans",
            callback_data="balance",
        )
    )

    keyboard.add(
        InlineKeyboardButton(
            "ℹ️ Yordam",
            callback_data="help",
        )
    )

    return keyboard


@bot.message_handler(commands=["start"])
def command_start(message):
    user = message.from_user

    upsert_user(
        telegram_id=user.id,
        username=user.username,
        first_name=user.first_name,
        last_name=user.last_name,
    )

    name = html.escape(
        user.first_name or "foydalanuvchi"
    )

    bot.send_message(
        message.chat.id,
        (
            f"Salom, <b>{name}</b>! 👋\n\n"
            "Bu reward Mini App.\n"
            "Reklamani muvaffaqiyatli ko‘rib, "
            f"har {REWARD_EVERY_ADS} ta tasdiqlangan reklamaga "
            "1 ⭐ olishingiz mumkin.\n\n"
            f"Minimal withdrawal: {WITHDRAW_MINIMUM} ⭐"
        ),
        reply_markup=main_menu(),
    )


@bot.message_handler(commands=["balance"])
def command_balance(message):
    user = message.from_user

    upsert_user(
        telegram_id=user.id,
        username=user.username,
        first_name=user.first_name,
        last_name=user.last_name,
    )

    stats = user_stats(user.id)

    bot.send_message(
        message.chat.id,
        (
            "⭐ <b>Balans</b>\n\n"
            f"Balans: <b>{stats['balance']} ⭐</b>\n"
            f"Ko‘rilgan reklamalar: <b>{stats['total_ads']}</b>\n"
            f"Keyingi ⭐ progress: "
            f"<b>{stats['progress_ads']}/{stats['reward_every']}</b>\n\n"
            f"Minimal withdrawal: <b>{WITHDRAW_MINIMUM} ⭐</b>"
        ),
        reply_markup=main_menu(),
    )


@bot.message_handler(commands=["withdraw"])
def command_withdraw(message):
    stats = user_stats(message.from_user.id)

    bot.send_message(
        message.chat.id,
        (
            "💸 <b>Withdrawal</b>\n\n"
            f"Joriy balans: <b>{stats['balance']} ⭐</b>\n"
            f"Minimal miqdor: <b>{WITHDRAW_MINIMUM} ⭐</b>\n\n"
            "Withdrawal so‘rovini Mini App ichidan yuboring."
        ),
        reply_markup=main_menu(),
    )


@bot.message_handler(commands=["help"])
def command_help(message):
    bot.send_message(
        message.chat.id,
        (
            "ℹ️ <b>Yordam</b>\n\n"
            "/start — Mini App ochish\n"
            "/balance — balansni ko‘rish\n"
            "/withdraw — withdrawal ma’lumoti\n"
            "/help — yordam\n\n"
            f"Har {REWARD_EVERY_ADS} ta muvaffaqiyatli "
            "tasdiqlangan rewarded ad uchun 1 ⭐ beriladi."
        ),
        reply_markup=main_menu(),
    )


@bot.callback_query_handler(
    func=lambda call: call.data == "balance"
)
def callback_balance(call):
    try:
        user = call.from_user

        upsert_user(
            telegram_id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
        )

        stats = user_stats(user.id)

        bot.answer_callback_query(
            call.id,
            (
                f"Balans: {stats['balance']} ⭐ | "
                f"Ads: {stats['total_ads']}"
            ),
            show_alert=True,
        )

    except Exception:
        logger.exception("Bot balance callback error")
        bot.answer_callback_query(
            call.id,
            "Xatolik yuz berdi.",
            show_alert=True,
        )


@bot.callback_query_handler(
    func=lambda call: call.data == "help"
)
def callback_help(call):
    bot.answer_callback_query(
        call.id,
        "Har 10 ta tasdiqlangan rewarded ad = 1 ⭐",
        show_alert=True,
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(_error):
    return error_response(
        "NOT_FOUND",
        "Endpoint topilmadi.",
        404,
    )


@app.errorhandler(405)
def method_not_allowed(_error):
    return error_response(
        "METHOD_NOT_ALLOWED",
        "HTTP method ruxsat etilmagan.",
        405,
    )


@app.errorhandler(Exception)
def unhandled_exception(error):
    logger.exception(
        "Unhandled Flask exception: %s",
        error,
    )
    return error_response(
        "SERVER_ERROR",
        "Ichki server xatosi.",
        500,
    )


# ============================================================
# STARTUP
# ============================================================

def run_web():
    """
    Local/simple single-process mode.

    For production, use:
        gunicorn -w 2 -b 0.0.0.0:8080 app:app

    and separately:
        python app.py bot
    """
    app.run(
        host=HOST,
        port=PORT,
        debug=DEBUG,
        use_reloader=False,
        threaded=True,
    )


def run_bot():
    logger.info("Telegram bot polling started.")
    bot.infinity_polling(
        skip_pending=True,
        allowed_updates=[
            "message",
            "callback_query",
        ],
    )


def main():
    init_db()

    mode = (
        sys.argv[1].lower()
        if len(sys.argv) > 1
        else "all"
    )

    logger.info(
        "Starting reward application | mode=%s",
        mode,
    )

    if mode == "web":
        run_web()
        return

    if mode == "bot":
        run_bot()
        return

    if mode == "all":
        web_thread = threading.Thread(
            target=run_web,
            name="flask-web",
            daemon=True,
        )
        web_thread.start()

        run_bot()
        return

    print(
        "Usage:\n"
        "  python app.py all   # local/simple: web + bot\n"
        "  python app.py web   # web only\n"
        "  python app.py bot   # bot only\n"
    )


if __name__ == "__main__":
    main()
