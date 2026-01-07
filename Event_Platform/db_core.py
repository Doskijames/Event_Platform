# db_core.py (FULL - corrected to be compatible with photos_routes.py)
import os
import sqlite3
from datetime import datetime, timezone
from flask import current_app, g
from werkzeug.security import generate_password_hash


# -------------------- small helpers --------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def row_get(row, key, default=None):
    """Safely get a value from sqlite3.Row / dict-like rows."""
    if row is None:
        return default
    try:
        if hasattr(row, "keys") and key in row.keys():
            v = row[key]
            return default if v is None else v
        if isinstance(row, dict):
            v = row.get(key, default)
            return default if v is None else v
    except Exception:
        pass
    return default


# -------------------- DB connection --------------------
def _db_path_from_config() -> str:
    # app.py sets: app.config["DATABASE"] = os.path.abspath(db_path)
    # fallback: env DATABASE_PATH or app.db in current working directory
    try:
        p = current_app.config.get("DATABASE")
        if p:
            return p
    except Exception:
        pass
    return os.path.abspath(os.getenv("DATABASE_PATH", "app.db"))


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    # good defaults
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def get_db() -> sqlite3.Connection:
    # IMPORTANT: g is not a dict; use attribute
    if not hasattr(g, "db") or g.db is None:
        g.db = _connect(_db_path_from_config())
    return g.db


def close_db(e=None):
    db = getattr(g, "db", None)
    if db is not None:
        db.close()
        g.db = None


# -------------------- schema + migrations --------------------
def _table_exists(db: sqlite3.Connection, table: str) -> bool:
    r = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return r is not None


def _column_exists(db: sqlite3.Connection, table: str, col: str) -> bool:
    try:
        rows = db.execute(f"PRAGMA table_info({table})").fetchall()
        return any(r["name"] == col for r in rows)
    except Exception:
        return False


def _add_column_if_missing(db: sqlite3.Connection, table: str, col: str, col_def: str):
    if _table_exists(db, table) and not _column_exists(db, table, col):
        db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")


def init_db():
    db = get_db()

    # ---- USERS ----
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,

            role TEXT DEFAULT 'user',
            is_verified INTEGER DEFAULT 0,

            failed_login_attempts INTEGER DEFAULT 0,
            is_locked INTEGER DEFAULT 0,

            otp_hash TEXT DEFAULT '',
            otp_expires_at TEXT DEFAULT '',
            otp_purpose TEXT DEFAULT 'verify',

            created_at TEXT DEFAULT ''
        )
        """
    )

    # Migrations for older user tables
    _add_column_if_missing(db, "users", "role", "TEXT DEFAULT 'user'")
    _add_column_if_missing(db, "users", "is_verified", "INTEGER DEFAULT 0")
    _add_column_if_missing(db, "users", "failed_login_attempts", "INTEGER DEFAULT 0")
    _add_column_if_missing(db, "users", "is_locked", "INTEGER DEFAULT 0")
    _add_column_if_missing(db, "users", "otp_hash", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "users", "otp_expires_at", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "users", "otp_purpose", "TEXT DEFAULT 'verify'")
    _add_column_if_missing(db, "users", "created_at", "TEXT DEFAULT ''")

    # ---- EVENTS ----
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,

            name TEXT NOT NULL,
            date_iso TEXT NOT NULL,
            location TEXT NOT NULL,
            description TEXT NOT NULL,

            passcode TEXT NOT NULL,
            owner_user_id INTEGER,

            cover_image TEXT DEFAULT '',
            created_at TEXT DEFAULT '',

            FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )

    # Migrations for older events tables
    _add_column_if_missing(db, "events", "slug", "TEXT")
    _add_column_if_missing(db, "events", "name", "TEXT")
    _add_column_if_missing(db, "events", "date_iso", "TEXT")
    _add_column_if_missing(db, "events", "location", "TEXT")
    _add_column_if_missing(db, "events", "description", "TEXT")
    _add_column_if_missing(db, "events", "passcode", "TEXT")
    _add_column_if_missing(db, "events", "owner_user_id", "INTEGER")
    _add_column_if_missing(db, "events", "cover_image", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "events", "created_at", "TEXT DEFAULT ''")

    # ---- SECTIONS ----
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS sections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            section_key TEXT NOT NULL,

            title TEXT DEFAULT '',
            visible INTEGER DEFAULT 1,

            content TEXT DEFAULT '',
            draft_content TEXT DEFAULT '',

            image TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,

            UNIQUE(event_id, section_key),
            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        )
        """
    )

    # Migrations for older sections tables
    _add_column_if_missing(db, "sections", "title", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "sections", "visible", "INTEGER DEFAULT 1")
    _add_column_if_missing(db, "sections", "content", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "sections", "draft_content", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "sections", "image", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "sections", "sort_order", "INTEGER DEFAULT 0")

    # ---- RSVP QUESTIONS ----
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS rsvp_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            position INTEGER NOT NULL DEFAULT 1,
            question TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'main',
            type TEXT NOT NULL DEFAULT 'text',
            allow_multi INTEGER NOT NULL DEFAULT 0,
            options TEXT NOT NULL DEFAULT '[]',
            required INTEGER NOT NULL DEFAULT 1,
            show_if_question INTEGER,
            show_if_value TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        )
        """
    )

    _add_column_if_missing(db, "rsvp_questions", "position", "INTEGER DEFAULT 1")
    _add_column_if_missing(db, "rsvp_questions", "kind", "TEXT DEFAULT 'main'")
    _add_column_if_missing(db, "rsvp_questions", "type", "TEXT DEFAULT 'text'")
    _add_column_if_missing(db, "rsvp_questions", "allow_multi", "INTEGER DEFAULT 0")
    _add_column_if_missing(db, "rsvp_questions", "options", "TEXT DEFAULT '[]'")
    _add_column_if_missing(db, "rsvp_questions", "required", "INTEGER DEFAULT 1")
    _add_column_if_missing(db, "rsvp_questions", "show_if_question", "INTEGER")
    _add_column_if_missing(db, "rsvp_questions", "show_if_value", "TEXT DEFAULT ''")

    # ---- RSVP RESPONSES ----
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS rsvp_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            user_id INTEGER,

            first_name TEXT NOT NULL DEFAULT '',
            last_name TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            whatsapp TEXT NOT NULL DEFAULT '',

            whatsapp_opt_in INTEGER NOT NULL DEFAULT 0,
            whatsapp_opt_in_at TEXT NOT NULL DEFAULT '',
            whatsapp_opt_in_source TEXT NOT NULL DEFAULT '',
            whatsapp_consent_version TEXT NOT NULL DEFAULT 'v1',

            answers TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT '',

            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )

    _add_column_if_missing(db, "rsvp_responses", "user_id", "INTEGER")
    _add_column_if_missing(db, "rsvp_responses", "first_name", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "rsvp_responses", "last_name", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "rsvp_responses", "email", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "rsvp_responses", "whatsapp", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "rsvp_responses", "whatsapp_opt_in", "INTEGER DEFAULT 0")
    _add_column_if_missing(db, "rsvp_responses", "whatsapp_opt_in_at", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "rsvp_responses", "whatsapp_opt_in_source", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "rsvp_responses", "whatsapp_consent_version", "TEXT DEFAULT 'v1'")
    _add_column_if_missing(db, "rsvp_responses", "answers", "TEXT DEFAULT '{}'")
    _add_column_if_missing(db, "rsvp_responses", "created_at", "TEXT DEFAULT ''")

    # =====================================================================
    # PHOTOS TABLES (needed by photos_routes.py)
    # =====================================================================

    # ---- EVENT PHOTOS ----
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS event_photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            file_name TEXT NOT NULL,
            uploader_user_id INTEGER,
            uploader_name TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
            FOREIGN KEY(uploader_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )

    _add_column_if_missing(db, "event_photos", "kind", "TEXT")
    _add_column_if_missing(db, "event_photos", "file_name", "TEXT")
    _add_column_if_missing(db, "event_photos", "uploader_user_id", "INTEGER")
    _add_column_if_missing(db, "event_photos", "uploader_name", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "event_photos", "created_at", "TEXT DEFAULT ''")

    # ---- PHOTOS DAY SETTINGS ----
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS photos_day_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL UNIQUE,
            token TEXT NOT NULL DEFAULT '',
            is_open INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        )
        """
    )

    _add_column_if_missing(db, "photos_day_settings", "token", "TEXT DEFAULT ''")
    _add_column_if_missing(db, "photos_day_settings", "is_open", "INTEGER DEFAULT 0")
    _add_column_if_missing(db, "photos_day_settings", "updated_at", "TEXT DEFAULT ''")

    db.commit()

    # Ensure default admin exists
    ensure_default_admin()


# -------------------- defaults --------------------
def ensure_default_admin():
    """
    Creates a default admin using env:
      DEFAULT_ADMIN_EMAIL
      DEFAULT_ADMIN_PASSWORD (recommended to add!)
    """
    db = get_db()

    admin_email = (os.getenv("DEFAULT_ADMIN_EMAIL") or "").strip().lower()
    if not admin_email:
        return

    # if exists, ensure it's admin + verified
    u = db.execute("SELECT * FROM users WHERE email=?", (admin_email,)).fetchone()
    if u:
        db.execute(
            "UPDATE users SET role='admin', is_verified=1, is_locked=0 WHERE id=?",
            (u["id"],),
        )
        db.commit()
        return

    pw = (os.getenv("DEFAULT_ADMIN_PASSWORD") or "Admin1234").strip()

    db.execute(
        """
        INSERT INTO users(email, password_hash, role, is_verified, failed_login_attempts, is_locked,
                          otp_hash, otp_expires_at, otp_purpose, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            admin_email,
            generate_password_hash(pw),
            "admin",
            1,
            0,
            0,
            "",
            "",
            "verify",
            now_iso(),
        ),
    )
    db.commit()
    print(f"✅ Default admin ensured: {admin_email} (password from DEFAULT_ADMIN_PASSWORD or Admin1234)")


def ensure_default_sections(event_id: int):
    """
    Ensures the sections rows exist for an event.
    """
    db = get_db()

    defaults = [
        ("home", "Home", 1, 0),
        ("story", "Our Story", 1, 10),
        ("meet-couple", "Meet the Couple", 1, 20),
        ("proposal", "The Proposal", 1, 30),
        ("tidbits", "Tidbits", 1, 40),
        ("qa", "Q&A", 1, 50),
        ("rsvp", "RSVP", 1, 60),
        ("photos", "Photos", 1, 70),
        ("photos-day", "Photos (Admin)", 1, 80),
    ]

    for key, title, visible, order in defaults:
        db.execute(
            """
            INSERT OR IGNORE INTO sections(event_id, section_key, title, visible, content, draft_content, image, sort_order)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (event_id, key, title, visible, "", "", "", order),
        )

    db.commit()
