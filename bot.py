import asyncio
import hashlib
import logging
import random
import re
import sqlite3
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from telegram import BotCommand, ReplyKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "safegate.db"
LOG_PATH = BASE_DIR / "bot.log"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[logging.FileHandler(LOG_PATH, encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger("safegate-ultra")

MAIN_MENU = ReplyKeyboardMarkup(
    [
        ["ℹ️ Информация", "👤 Профиль"],
        ["🛡 Советы по ИБ", "🔎 Проверить ввод"],
        ["🎭 Симуляция атаки", "📈 Мой риск"],
        ["🛰 IDS статус", "🧾 Мои нарушения"],
        ["📜 Команды", "⚙️ Админ-панель"],
    ],
    resize_keyboard=True,
)

CHECK_PROMPT = "Отправь текст одним сообщением, и я проверю его на базовые признаки риска."
VERIFY_PROMPT = "Отправь секретный код одним сообщением."
ADMIN_LOGIN_TTL_MINUTES = 10
SPAM_LIMIT = 6
SPAM_WINDOW_SECONDS = 10
MAX_VERIFY_FAILS = 3
MAX_SUSPICIOUS_EVENTS = 3
BLOCK_MINUTES = 5

ATTACK_SCENARIOS = {
    "sql": "SELECT * FROM users WHERE id = 1 OR 1=1;",
    "xss": "<script>alert('xss')</script>",
    "bruteforce": "Многократный подбор секретного кода.",
    "spam": "Частая отправка сообщений за короткий интервал.",
    "admin": "Попытка обращения к административным функциям без прав.",
}
HONEYPOT_COMMANDS = {"root", "token", "database", "admin_full"}


@dataclass
class Config:
    bot_token: str
    admin_id: Optional[int]
    secret_code: str


def load_config() -> Config:
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        raise RuntimeError(f"Файл .env не найден. Ожидался по пути: {env_path}")

    data = {}
    for line in env_path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")

    bot_token = data.get("BOT_TOKEN", "").strip()
    admin_id_raw = data.get("ADMIN_ID", "").strip()
    secret_code = data.get("SECRET_CODE", "safegate").strip()

    if not bot_token:
        raise RuntimeError(f"Не найден BOT_TOKEN. Проверен файл: {env_path}")

    try:
        admin_id = int(admin_id_raw) if admin_id_raw else None
    except ValueError as exc:
        raise RuntimeError("ADMIN_ID должен быть числом.") from exc

    return Config(bot_token=bot_token, admin_id=admin_id, secret_code=secret_code)


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            telegram_id INTEGER PRIMARY KEY,
            username TEXT,
            full_name TEXT,
            registered_at TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER,
            event_type TEXT,
            severity TEXT,
            details TEXT,
            created_at TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER,
            incident_type TEXT,
            severity TEXT,
            status TEXT,
            details TEXT,
            actions_taken TEXT,
            created_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def register_user(update: Update) -> None:
    user = update.effective_user
    if not user:
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT OR REPLACE INTO users (telegram_id, username, full_name, registered_at)
        VALUES (?, ?, ?, COALESCE((SELECT registered_at FROM users WHERE telegram_id=?), ?))
        """,
        (
            user.id,
            user.username or "",
            f"{user.first_name or ''} {user.last_name or ''}".strip(),
            user.id,
            datetime.now().isoformat(timespec="seconds"),
        ),
    )
    conn.commit()
    conn.close()


def log_event(telegram_id: Optional[int], event_type: str, details: str = "", severity: str = "info") -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO events (telegram_id, event_type, severity, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (telegram_id, event_type, severity, details[:1500], datetime.now().isoformat(timespec="seconds")),
    )
    conn.commit()
    conn.close()


def create_incident(
    telegram_id: Optional[int],
    incident_type: str,
    severity: str,
    details: str,
    actions_taken: str,
    status: str = "open",
) -> int:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO incidents (telegram_id, incident_type, severity, status, details, actions_taken, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            telegram_id,
            incident_type,
            severity,
            status,
            details[:1500],
            actions_taken[:1500],
            datetime.now().isoformat(timespec="seconds"),
        ),
    )
    incident_id = cur.lastrowid
    conn.commit()
    conn.close()
    return incident_id


def get_last_incident() -> Optional[tuple]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, telegram_id, incident_type, severity, status, details, actions_taken, created_at FROM incidents ORDER BY id DESC LIMIT 1"
    )
    row = cur.fetchone()
    conn.close()
    return row


def get_incident_by_id(incident_id: int) -> Optional[tuple]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, telegram_id, incident_type, severity, status, details, actions_taken, created_at FROM incidents WHERE id = ?",
        (incident_id,),
    )
    row = cur.fetchone()
    conn.close()
    return row


def is_admin(user_id: Optional[int], config: Config) -> bool:
    return user_id is not None and config.admin_id is not None and user_id == config.admin_id


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def analyze_text(text: str) -> list[str]:
    findings = []
    if len(text) > 300:
        findings.append("слишком длинный ввод")
    if re.search(r"(<script|</script>|select\s+\*|drop\s+table|union\s+select|or\s+1=1|insert\s+into|delete\s+from)", text, flags=re.I):
        findings.append("похоже на инъекцию или опасную конструкцию")
    if re.search(r"[<>]{2,}|[\"'`;]{3,}", text):
        findings.append("подозрительные спецсимволы")
    if re.search(r"(token|password|passwd|secret|api[_-]?key|private key)", text, flags=re.I):
        findings.append("возможная чувствительная информация")
    if re.search(r"https?://", text, flags=re.I):
        findings.append("содержит ссылку")
    return findings


def get_user_stats(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> dict:
    stats = context.application.user_data[user_id]
    stats.setdefault("verify_failures", 0)
    stats.setdefault("suspicious_count", 0)
    stats.setdefault("spam_warns", 0)
    stats.setdefault("message_times", deque(maxlen=12))
    stats.setdefault("awaiting", None)
    stats.setdefault("blocked_until", None)
    stats.setdefault("risk_score", 0)
    stats.setdefault("otp_code", None)
    stats.setdefault("otp_expiry", None)
    stats.setdefault("admin_session_until", None)
    stats.setdefault("last_incident_id", None)
    return stats


def remaining_block_text(blocked_until_iso: str) -> str:
    blocked_until = datetime.fromisoformat(blocked_until_iso)
    left = max(0, int((blocked_until - datetime.now()).total_seconds()))
    minutes = left // 60
    seconds = left % 60
    return f"{minutes} мин {seconds} сек" if minutes else f"{seconds} сек"


def is_user_blocked(stats: dict) -> bool:
    blocked_until_iso = stats.get("blocked_until")
    if not blocked_until_iso:
        return False
    blocked_until = datetime.fromisoformat(blocked_until_iso)
    if datetime.now() >= blocked_until:
        stats["blocked_until"] = None
        stats["verify_failures"] = 0
        stats["suspicious_count"] = 0
        return False
    return True


def block_user(stats: dict) -> None:
    stats["blocked_until"] = (datetime.now() + timedelta(minutes=BLOCK_MINUTES)).isoformat(timespec="seconds")


def add_risk(stats: dict, value: int) -> None:
    stats["risk_score"] = max(0, stats.get("risk_score", 0) + value)


def get_risk_level(stats: dict) -> tuple[str, str]:
    score = stats.get("risk_score", 0)
    if score >= 16:
        return "критический", "🔴"
    if score >= 10:
        return "высокий", "🟠"
    if score >= 5:
        return "повышенный", "🟡"
    return "нормальный", "🟢"


def admin_session_active(stats: dict) -> bool:
    until = stats.get("admin_session_until")
    if not until:
        return False
    expiry = datetime.fromisoformat(until)
    if datetime.now() >= expiry:
        stats["admin_session_until"] = None
        return False
    return True


async def notify_admin(app: Application, config: Config, message: str) -> None:
    if config.admin_id:
        try:
            await app.bot.send_message(chat_id=config.admin_id, text=message)
        except Exception as exc:
            logger.warning("Не удалось отправить уведомление админу: %s", exc)


async def send_menu(update: Update, text: str) -> None:
    await update.message.reply_text(text, reply_markup=MAIN_MENU, parse_mode=ParseMode.HTML)


async def show_help(update: Update) -> None:
    text = (
        "<b>Команды и подсказки</b>\n\n"
        "/start — запуск бота и показ меню\n"
        "/help — список команд\n"
        "/menu — открыть меню\n"
        "/info — описание проекта\n"
        "/security — рекомендации по ИБ\n"
        "/profile — профиль и статус пользователя\n"
        "/check текст — анализ введённого текста\n"
        "/verify код — проверка секретного кода\n"
        "/violations — личная статистика нарушений\n"
        "/risk — оценка уровня риска\n"
        "/ids — статус встроенной IDS\n"
        "/simulate [sql|xss|bruteforce|spam|admin] — симуляция атаки\n"
        "/admin — вход в админ-панель через PIN\n"
        "/admin_login PIN — подтверждение входа администратора\n"
        "/dashboard — центр мониторинга безопасности\n"
        "/logs — последние события\n"
        "/incident [id|latest] — отчёт по инциденту\n"
        "/report — PDF-отчёт по безопасности\n\n"
        "Honeypot-команды: /root, /token, /database, /admin_full"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    register_user(update)
    user_id = update.effective_user.id if update.effective_user else None
    log_event(user_id, "start", "Запуск бота")
    text = (
        "🛡 <b>SafeGate Ultra Bot</b>\n\n"
        "Демонстрационный Telegram-бот по защите информации.\n"
        "Он показывает контроль доступа, журналирование, IDS, honeypot-команды,\n"
        "риск-скоринг, симуляции атак и формирование отчётов по инцидентам.\n\n"
        "Открой /help или используй меню ниже."
    )
    await send_menu(update, text)


async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    log_event(update.effective_user.id if update.effective_user else None, "menu", "Открыто меню")
    await send_menu(update, "Главное меню открыто.")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await show_help(update)


async def info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>О боте</b>\n\n"
        "SafeGate Ultra Bot — учебный прототип защищённого Telegram-бота с функциями обнаружения,\n"
        "регистрации и анализа инцидентов информационной безопасности."
    )
    log_event(update.effective_user.id if update.effective_user else None, "info", "Просмотр описания")
    await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


async def security(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>Рекомендации по защите Telegram-ботов</b>\n\n"
        "• хранить токен вне исходного кода;\n"
        "• ограничивать права по Telegram ID и доп. подтверждению;\n"
        "• валидировать пользовательский ввод;\n"
        "• журналировать критические события;\n"
        "• отслеживать brute force и flood;\n"
        "• применять honeypot и мониторинг инцидентов;\n"
        "• формировать отчётность по безопасности."
    )
    log_event(update.effective_user.id if update.effective_user else None, "security", "Просмотр рекомендаций")
    await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


async def profile(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    register_user(update)
    stats = get_user_stats(context, user.id)
    blocked = "нет"
    if stats.get("blocked_until") and is_user_blocked(stats):
        blocked = remaining_block_text(stats["blocked_until"])
    risk_level, emoji = get_risk_level(stats)
    text = (
        "<b>Профиль пользователя</b>\n\n"
        f"ID: <code>{user.id}</code>\n"
        f"Username: @{user.username if user.username else 'не указан'}\n"
        f"Имя: {user.full_name}\n"
        f"Риск-профиль: {emoji} {risk_level}\n"
        f"Ошибок проверки кода: {stats['verify_failures']}\n"
        f"Подозрительных действий: {stats['suspicious_count']}\n"
        f"Блокировка: {blocked}"
    )
    log_event(user.id, "profile", "Просмотр профиля")
    await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


async def violations(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    stats = get_user_stats(context, user.id)
    blocked_text = "активной блокировки нет"
    if stats.get("blocked_until") and is_user_blocked(stats):
        blocked_text = f"блокировка ещё на {remaining_block_text(stats['blocked_until'])}"
    text = (
        "<b>Статистика безопасности</b>\n\n"
        f"Неудачных проверок кода: {stats['verify_failures']}\n"
        f"Подозрительных вводов: {stats['suspicious_count']}\n"
        f"Предупреждений за спам: {stats['spam_warns']}\n"
        f"Статус: {blocked_text}"
    )
    log_event(user.id, "violations", "Просмотр статистики нарушений")
    await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


async def risk(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    stats = get_user_stats(context, user.id)
    reasons = []
    if stats["verify_failures"]:
        reasons.append(f"неверные проверки кода: {stats['verify_failures']}")
    if stats["suspicious_count"]:
        reasons.append(f"подозрительные вводы: {stats['suspicious_count']}")
    if stats["spam_warns"]:
        reasons.append(f"антиспам-предупреждения: {stats['spam_warns']}")
    risk_level, emoji = get_risk_level(stats)
    text = (
        f"<b>Оценка риска пользователя</b>\n\nТекущий уровень: {emoji} <b>{risk_level}</b>\n"
        f"Risk score: <code>{stats['risk_score']}</code>\n"
        f"Причины: {'; '.join(reasons) if reasons else 'негативные факторы не обнаружены'}"
    )
    log_event(user.id, "risk_view", f"risk_score={stats['risk_score']}")
    await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


async def ids(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
    rows = dict(cur.fetchall())
    cur.execute("SELECT COUNT(*) FROM incidents")
    total = cur.fetchone()[0]
    conn.close()
    text = (
        "<b>Статус встроенной IDS</b>\n\n"
        "Система обнаружения активна.\n"
        f"Всего инцидентов: {total}\n"
        f"Критических: {rows.get('critical', 0)}\n"
        f"Высоких: {rows.get('high', 0)}\n"
        f"Средних: {rows.get('medium', 0)}\n"
        f"Низких: {rows.get('low', 0)}"
    )
    log_event(update.effective_user.id if update.effective_user else None, "ids_view", "Просмотр IDS статуса")
    await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


async def check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    stats = get_user_stats(context, user.id)
    if is_user_blocked(stats):
        await update.message.reply_text(
            f"⛔ Временная блокировка активна ещё {remaining_block_text(stats['blocked_until'])}.",
            reply_markup=MAIN_MENU,
        )
        return

    if context.args:
        await process_check(update, context, " ".join(context.args))
        return

    stats["awaiting"] = "check"
    await update.message.reply_text(CHECK_PROMPT, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


async def process_check(update: Update, context: ContextTypes.DEFAULT_TYPE, text_to_check: str) -> None:
    user = update.effective_user
    stats = get_user_stats(context, user.id)
    findings = analyze_text(text_to_check)
    stats["awaiting"] = None

    if findings:
        stats["suspicious_count"] += 1
        add_risk(stats, 3)
        details = "; ".join(findings)
        incident_id = create_incident(
            user.id,
            "suspicious_input",
            "medium",
            f"Текст: {text_to_check[:300]} | Признаки: {details}",
            "Ввод отклонён, событие записано, администратор уведомлён.",
        )
        stats["last_incident_id"] = incident_id
        response = "<b>Результат анализа</b>\n\nОбнаружено:\n- " + "\n- ".join(findings)
        log_event(user.id, "suspicious_input", details, "medium")
        await notify_admin(
            context.application,
            context.bot_data["config"],
            f"⚠️ Инцидент #{incident_id}: подозрительный ввод от {user.id}",
        )
        if stats["suspicious_count"] >= MAX_SUSPICIOUS_EVENTS:
            block_user(stats)
            add_risk(stats, 4)
            response += f"\n\n⛔ Из-за повторяющихся подозрительных действий доступ ограничен на {BLOCK_MINUTES} минут."
            log_event(user.id, "user_blocked", "Блокировка за подозрительные вводы", "high")
    else:
        response = "<b>Результат анализа</b>\n\nПодозрительных признаков не обнаружено."
        log_event(user.id, "check_ok", "Проверка текста без замечаний")

    await update.message.reply_text(response, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


async def verify(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    stats = get_user_stats(context, user.id)
    if is_user_blocked(stats):
        await update.message.reply_text(
            f"⛔ Временная блокировка активна ещё {remaining_block_text(stats['blocked_until'])}.",
            reply_markup=MAIN_MENU,
        )
        return

    if context.args:
        await process_verify(update, context, " ".join(context.args).strip())
        return

    stats["awaiting"] = "verify"
    await update.message.reply_text(VERIFY_PROMPT, reply_markup=MAIN_MENU)


async def process_verify(update: Update, context: ContextTypes.DEFAULT_TYPE, entered: str) -> None:
    user = update.effective_user
    stats = get_user_stats(context, user.id)
    config: Config = context.bot_data["config"]
    stats["awaiting"] = None
    ok = hash_text(entered) == hash_text(config.secret_code)

    if ok:
        stats["verify_failures"] = 0
        add_risk(stats, -2)
        log_event(user.id, "verify_success", "Успешная проверка кода")
        await update.message.reply_text("✅ Код подтверждён.", reply_markup=MAIN_MENU)
    else:
        stats["verify_failures"] += 1
        add_risk(stats, 2)
        log_event(user.id, "verify_failed", "Неуспешная проверка кода", "medium")
        response = f"❌ Код неверный. Попытка {stats['verify_failures']} из {MAX_VERIFY_FAILS}."
        if stats["verify_failures"] >= MAX_VERIFY_FAILS:
            block_user(stats)
            add_risk(stats, 5)
            incident_id = create_incident(
                user.id,
                "bruteforce_detected",
                "high",
                f"Пользователь превысил лимит ошибок проверки кода: {stats['verify_failures']}",
                f"Пользователь заблокирован на {BLOCK_MINUTES} минут, администратор уведомлён.",
            )
            stats["last_incident_id"] = incident_id
            log_event(user.id, "user_blocked", "Блокировка за многократные ошибки verify", "high")
            await notify_admin(
                context.application,
                config,
                f"⛔ Инцидент #{incident_id}: пользователь {user.id} заблокирован после ошибок проверки кода.",
            )
            response += f"\n⛔ Доступ ограничен на {BLOCK_MINUTES} минут."
        await update.message.reply_text(response, reply_markup=MAIN_MENU)


async def simulate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    stats = get_user_stats(context, user.id)
    scenario = (context.args[0].lower() if context.args else "").strip()

    if not scenario:
        available = ", ".join(ATTACK_SCENARIOS.keys())
        await update.message.reply_text(
            f"Выбери сценарий: /simulate sql, /simulate xss, /simulate bruteforce, /simulate spam, /simulate admin\nДоступно: {available}",
            reply_markup=MAIN_MENU,
        )
        return
    if scenario not in ATTACK_SCENARIOS:
        await update.message.reply_text("Неизвестный сценарий. Используй /simulate sql|xss|bruteforce|spam|admin", reply_markup=MAIN_MENU)
        return

    severity = "medium"
    actions = "Событие смоделировано, зафиксировано и отображено в учебном режиме."
    details = ATTACK_SCENARIOS[scenario]
    add_risk(stats, 1)

    if scenario in {"bruteforce", "admin"}:
        severity = "high"
    if scenario == "spam":
        severity = "low"

    incident_id = create_incident(user.id, f"simulation_{scenario}", severity, details, actions, status="simulated")
    stats["last_incident_id"] = incident_id
    log_event(user.id, "attack_simulation", f"scenario={scenario}", severity)

    response = (
        f"<b>Симуляция атаки: {scenario}</b>\n\n"
        f"Полезная нагрузка: <code>{details}</code>\n"
        f"Реакция системы: обнаружение, журналирование, классификация по критичности, формирование инцидента #{incident_id}.\n"
        f"Критичность: {severity}."
    )
    await update.message.reply_text(response, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


def ensure_admin_session(user_id: Optional[int], context: ContextTypes.DEFAULT_TYPE) -> tuple[bool, str]:
    config: Config = context.bot_data["config"]
    if not is_admin(user_id, config):
        return False, "Доступ запрещён."
    stats = get_user_stats(context, user_id)
    if not admin_session_active(stats):
        return False, "Сессия администратора не подтверждена. Используй /admin и затем /admin_login PIN."
    return True, ""


async def admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    user_id = update.effective_user.id if update.effective_user else None
    if not is_admin(user_id, config):
        incident_id = create_incident(
            user_id,
            "admin_access_denied",
            "high",
            "Попытка доступа к административной панели без прав.",
            "Доступ отклонён, администратор уведомлён.",
        )
        log_event(user_id, "admin_denied", "Попытка доступа к панели администратора", "high")
        await notify_admin(context.application, config, f"🚫 Инцидент #{incident_id}: попытка доступа к /admin от {user_id}")
        await update.message.reply_text("Доступ запрещён.", reply_markup=MAIN_MENU)
        return

    stats = get_user_stats(context, user_id)
    otp = f"{random.randint(100000, 999999)}"
    stats["otp_code"] = otp
    stats["otp_expiry"] = (datetime.now() + timedelta(minutes=3)).isoformat(timespec="seconds")
    log_event(user_id, "admin_otp_generated", "Сгенерирован PIN для входа в админ-панель")
    await update.message.reply_text(
        f"🔐 Для входа в админ-панель используй команду <code>/admin_login {otp}</code> в течение 3 минут.",
        parse_mode=ParseMode.HTML,
        reply_markup=MAIN_MENU,
    )


async def admin_login(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config: Config = context.bot_data["config"]
    user_id = update.effective_user.id if update.effective_user else None
    if not is_admin(user_id, config):
        await update.message.reply_text("Доступ запрещён.", reply_markup=MAIN_MENU)
        return
    if not context.args:
        await update.message.reply_text("Используй: /admin_login 123456", reply_markup=MAIN_MENU)
        return

    stats = get_user_stats(context, user_id)
    otp = stats.get("otp_code")
    expiry = stats.get("otp_expiry")
    if not otp or not expiry:
        await update.message.reply_text("Сначала вызови /admin для получения PIN.", reply_markup=MAIN_MENU)
        return
    if datetime.now() >= datetime.fromisoformat(expiry):
        stats["otp_code"] = None
        stats["otp_expiry"] = None
        await update.message.reply_text("PIN истёк. Запроси новый через /admin.", reply_markup=MAIN_MENU)
        return
    if context.args[0].strip() != otp:
        log_event(user_id, "admin_login_failed", "Неверный PIN администратора", "high")
        await update.message.reply_text("Неверный PIN.", reply_markup=MAIN_MENU)
        return

    stats["otp_code"] = None
    stats["otp_expiry"] = None
    stats["admin_session_until"] = (datetime.now() + timedelta(minutes=ADMIN_LOGIN_TTL_MINUTES)).isoformat(timespec="seconds")
    log_event(user_id, "admin_login_success", "Вход администратора подтверждён")
    await update.message.reply_text(
        "✅ Административная сессия активна на 10 минут. Доступны /dashboard, /logs, /incident, /report.",
        reply_markup=MAIN_MENU,
    )


async def dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else None
    ok, message = ensure_admin_session(user_id, context)
    if not ok:
        await update.message.reply_text(message, reply_markup=MAIN_MENU)
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    users_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM events")
    events_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM incidents")
    incidents_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'critical'")
    critical_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'simulated')")
    active_incidents = cur.fetchone()[0]
    cur.execute("SELECT incident_type, COUNT(*) AS c FROM incidents GROUP BY incident_type ORDER BY c DESC LIMIT 3")
    top_incidents = cur.fetchall()
    conn.close()

    top_text = "\n".join([f"• {name}: {count}" for name, count in top_incidents]) if top_incidents else "нет данных"
    text = (
        "<b>Панель мониторинга безопасности</b>\n\n"
        f"Пользователей: {users_count}\n"
        f"Событий в журнале: {events_count}\n"
        f"Инцидентов: {incidents_count}\n"
        f"Критических: {critical_count}\n"
        f"Активных/симулированных: {active_incidents}\n\n"
        f"Топ инцидентов:\n{top_text}"
    )
    log_event(user_id, "dashboard_open", "Открыт центр мониторинга")
    await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


async def logs(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else None
    ok, message = ensure_admin_session(user_id, context)
    if not ok:
        await update.message.reply_text(message, reply_markup=MAIN_MENU)
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT created_at, telegram_id, event_type, severity, details FROM events ORDER BY id DESC LIMIT 15")
    rows = cur.fetchall()
    conn.close()

    if not rows:
        await update.message.reply_text("Журнал пока пуст.", reply_markup=MAIN_MENU)
        return

    lines = ["<b>Последние события</b>"]
    for created_at, telegram_id, event_type, severity, details in rows:
        lines.append(f"\n<code>{created_at}</code>\nuser={telegram_id} | {event_type} | {severity}\n{details[:120]}")
    log_event(user_id, "logs_open", "Просмотр журнала")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


async def incident(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else None
    ok, message = ensure_admin_session(user_id, context)
    if not ok:
        await update.message.reply_text(message, reply_markup=MAIN_MENU)
        return

    if context.args and context.args[0].lower() != "latest":
        try:
            incident_id = int(context.args[0])
        except ValueError:
            await update.message.reply_text("Используй /incident latest или /incident 12", reply_markup=MAIN_MENU)
            return
        row = get_incident_by_id(incident_id)
    else:
        row = get_last_incident()

    if not row:
        await update.message.reply_text("Инциденты пока не зарегистрированы.", reply_markup=MAIN_MENU)
        return

    inc_id, tg_id, inc_type, severity, status, details, actions_taken, created_at = row
    text = (
        "<b>Отчёт об инциденте</b>\n\n"
        f"ID: {inc_id}\n"
        f"Пользователь: {tg_id}\n"
        f"Дата: {created_at}\n"
        f"Тип: {inc_type}\n"
        f"Критичность: {severity}\n"
        f"Статус: {status}\n"
        f"Описание: {details}\n"
        f"Принятые меры: {actions_taken}"
    )
    log_event(user_id, "incident_view", f"incident_id={inc_id}")
    await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=MAIN_MENU)


def _register_font() -> str:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "C:/Windows/Fonts/arial.ttf",
    ]
    for font_path in candidates:
        if Path(font_path).exists():
            pdfmetrics.registerFont(TTFont("SafeGateFont", font_path))
            return "SafeGateFont"
    return "Helvetica"


def create_pdf_report() -> Path:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    users_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM events")
    events_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM incidents")
    incidents_count = cur.fetchone()[0]
    cur.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
    by_severity = dict(cur.fetchall())
    cur.execute("SELECT incident_type, COUNT(*) AS c FROM incidents GROUP BY incident_type ORDER BY c DESC LIMIT 10")
    top_incidents = cur.fetchall()
    cur.execute("SELECT created_at, telegram_id, incident_type, severity FROM incidents ORDER BY id DESC LIMIT 10")
    latest = cur.fetchall()
    conn.close()

    report_path = REPORTS_DIR / f"safegate_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    font_name = _register_font()
    c = canvas.Canvas(str(report_path), pagesize=A4)
    width, height = A4
    x, y = 40, height - 50

    def line(text: str, step: int = 16):
        nonlocal y
        if y < 60:
            c.showPage()
            c.setFont(font_name, 11)
            y = height - 50
        c.drawString(x, y, text[:110])
        y -= step

    c.setFont(font_name, 14)
    line("SafeGate Ultra Bot — отчет по безопасности", 22)
    c.setFont(font_name, 11)
    line(f"Дата формирования: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    line(f"Пользователей: {users_count}")
    line(f"Событий: {events_count}")
    line(f"Инцидентов: {incidents_count}")
    line(f"Critical: {by_severity.get('critical', 0)} | High: {by_severity.get('high', 0)} | Medium: {by_severity.get('medium', 0)} | Low: {by_severity.get('low', 0)}", 22)
    line("Топ инцидентов:")
    for inc_type, count in top_incidents or [("нет данных", 0)]:
        line(f"- {inc_type}: {count}")
    line("", 8)
    line("Последние инциденты:")
    for created_at, tg_id, inc_type, severity in latest or [("-", "-", "нет данных", "-")]:
        line(f"- {created_at} | user={tg_id} | {inc_type} | {severity}")
    line("", 8)
    line("Рекомендации:")
    for item in [
        "Регулярно перевыпускать токен после его раскрытия.",
        "Ограничивать админ-доступ по Telegram ID и PIN-подтверждению.",
        "Контролировать подозрительный ввод и brute force.",
        "Периодически анализировать журнал событий и отчеты.",
    ]:
        line(f"- {item}")
    c.save()
    return report_path


async def report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else None
    ok, message = ensure_admin_session(user_id, context)
    if not ok:
        await update.message.reply_text(message, reply_markup=MAIN_MENU)
        return

    path = create_pdf_report()
    log_event(user_id, "report_generated", path.name)
    await update.message.reply_document(document=path.open("rb"), filename=path.name, caption="PDF-отчёт по безопасности готов.")


async def check_rate_limit(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    if not user:
        return False
    stats = get_user_stats(context, user.id)
    if is_user_blocked(stats):
        await update.message.reply_text(
            f"⛔ Временная блокировка активна ещё {remaining_block_text(stats['blocked_until'])}.",
            reply_markup=MAIN_MENU,
        )
        return True

    now = datetime.now().timestamp()
    message_times: deque = stats["message_times"]
    message_times.append(now)
    recent = [t for t in message_times if now - t <= SPAM_WINDOW_SECONDS]
    if len(recent) > SPAM_LIMIT:
        stats["spam_warns"] += 1
        add_risk(stats, 3)
        log_event(user.id, "spam_detected", f"Более {SPAM_LIMIT} сообщений за {SPAM_WINDOW_SECONDS} сек", "medium")
        if stats["spam_warns"] >= 2:
            block_user(stats)
            incident_id = create_incident(
                user.id,
                "spam_detected",
                "high",
                f"Зафиксирован флуд: более {SPAM_LIMIT} сообщений за {SPAM_WINDOW_SECONDS} секунд.",
                f"Пользователь заблокирован на {BLOCK_MINUTES} минут, администратор уведомлён.",
            )
            stats["last_incident_id"] = incident_id
            await notify_admin(
                context.application,
                context.bot_data["config"],
                f"⛔ Инцидент #{incident_id}: пользователь {user.id} заблокирован из-за спама.",
            )
            await update.message.reply_text(
                f"⛔ Слишком много запросов. Доступ ограничен на {BLOCK_MINUTES} минут.",
                reply_markup=MAIN_MENU,
            )
        else:
            await update.message.reply_text(
                "⚠️ Слишком много сообщений подряд. Уменьши частоту запросов.",
                reply_markup=MAIN_MENU,
            )
        return True
    return False


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user or not update.message:
        return

    register_user(update)
    if await check_rate_limit(update, context):
        return

    stats = get_user_stats(context, user.id)
    text = (update.message.text or "").strip()

    button_map = {
        "ℹ️ Информация": info,
        "👤 Профиль": profile,
        "🛡 Советы по ИБ": security,
        "🔎 Проверить ввод": check,
        "🎭 Симуляция атаки": simulate,
        "📈 Мой риск": risk,
        "🛰 IDS статус": ids,
        "🧾 Мои нарушения": violations,
        "📜 Команды": help_command,
        "⚙️ Админ-панель": admin,
    }
    if text in button_map:
        await button_map[text](update, context)
        return

    awaiting = stats.get("awaiting")
    if awaiting == "check":
        await process_check(update, context, text)
        return
    if awaiting == "verify":
        await process_verify(update, context, text)
        return

    log_event(user.id, "free_text", text[:150])
    await update.message.reply_text(
        "Я не понял запрос. Используй меню или /help. Для демонстрации атак доступна команда /simulate.",
        reply_markup=MAIN_MENU,
    )


async def honeypot(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else None
    command = update.message.text.split()[0].lstrip("/") if update.message and update.message.text else "unknown"
    incident_id = create_incident(
        user_id,
        f"honeypot_{command}",
        "critical",
        f"Активирована honeypot-команда /{command}.",
        "Событие классифицировано как разведка/попытка эскалации привилегий. Администратор уведомлён.",
    )
    log_event(user_id, "honeypot_triggered", f"/{command}", "critical")
    if update.effective_user:
        add_risk(get_user_stats(context, update.effective_user.id), 6)
    await notify_admin(context.application, context.bot_data["config"], f"🚨 Критический инцидент #{incident_id}: активирована honeypot-команда /{command} пользователем {user_id}")
    await update.message.reply_text(
        "🚨 Действие классифицировано как попытка несанкционированного доступа. Событие записано.",
        reply_markup=MAIN_MENU,
    )


async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else None
    log_event(user_id, "unknown_command", update.message.text if update.message else "", "low")
    await update.message.reply_text("Неизвестная команда. Используй /help", reply_markup=MAIN_MENU)


async def post_init(app: Application) -> None:
    bot = await app.bot.get_me()
    await app.bot.set_my_commands(
        [
            BotCommand("start", "Запустить бота и открыть меню"),
            BotCommand("help", "Список команд"),
            BotCommand("menu", "Открыть кнопочное меню"),
            BotCommand("info", "Информация о проекте"),
            BotCommand("security", "Советы по защите информации"),
            BotCommand("profile", "Мой профиль и статус"),
            BotCommand("check", "Проверить ввод на риски"),
            BotCommand("verify", "Проверить секретный код"),
            BotCommand("violations", "Мои нарушения"),
            BotCommand("risk", "Оценить уровень риска"),
            BotCommand("ids", "Статус встроенной IDS"),
            BotCommand("simulate", "Запустить симуляцию атаки"),
            BotCommand("admin", "Запросить PIN администратора"),
            BotCommand("admin_login", "Подтвердить вход администратора"),
            BotCommand("dashboard", "Центр мониторинга безопасности"),
            BotCommand("logs", "Просмотреть журнал событий"),
            BotCommand("incident", "Отчёт по инциденту"),
            BotCommand("report", "Сгенерировать PDF-отчёт"),
        ]
    )
    logger.info("Бот запущен: @%s", bot.username)


async def main() -> None:
    config = load_config()
    init_db()

    application = Application.builder().token(config.bot_token).post_init(post_init).build()
    application.bot_data["config"] = config

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("menu", menu))
    application.add_handler(CommandHandler("info", info))
    application.add_handler(CommandHandler("security", security))
    application.add_handler(CommandHandler("profile", profile))
    application.add_handler(CommandHandler("check", check))
    application.add_handler(CommandHandler("verify", verify))
    application.add_handler(CommandHandler("violations", violations))
    application.add_handler(CommandHandler("risk", risk))
    application.add_handler(CommandHandler("ids", ids))
    application.add_handler(CommandHandler("simulate", simulate))
    application.add_handler(CommandHandler("admin", admin))
    application.add_handler(CommandHandler("admin_login", admin_login))
    application.add_handler(CommandHandler("dashboard", dashboard))
    application.add_handler(CommandHandler("logs", logs))
    application.add_handler(CommandHandler("incident", incident))
    application.add_handler(CommandHandler("report", report))
    for hp in HONEYPOT_COMMANDS:
        application.add_handler(CommandHandler(hp, honeypot))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    application.add_handler(MessageHandler(filters.COMMAND, unknown))

    logger.info("Запуск polling...")
    await application.initialize()
    await application.start()
    await application.updater.start_polling(drop_pending_updates=True)
    try:
        await asyncio.Event().wait()
    finally:
        await application.updater.stop()
        await application.stop()
        await application.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
