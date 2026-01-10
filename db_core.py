
# db_core.py
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional, Set

from flask import current_app, g
from werkzeug.security import generate_password_hash

import psycopg2
import psycopg2.extras


# ----------------------------
# Small helpers
# ----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def using_postgres() -> bool:
    return bool(os.getenv("DATABASE_URL"))


def _sqlite_db_path() -> str:
    """
    Prefer Flask config DATABASE, fallback to env var DATABASE_PATH, fallback to app.db.

    NOTE: SQLite creates a NEW empty file if the path doesn't exist.
    This is the root cause of "no such table: events" when deploys / instances change.
    We guard against that elsewhere by ensuring schema exists on each connection.
    """
    try:
        p = current_app.config.get("DATABASE")
        if p:
            return p
    except Exception:
        pass
    return os.path.abspath(os.getenv("DATABASE_PATH", "app.db"))


def row_get(row, key, default=None):
    """
    Works with:
    - sqlite3.Row (SQLite)
    - dict rows (Postgres RealDictCursor)
    """
    if row is None:
        return default
    if isinstance(row, dict):
        v = row.get(key, default)
        return default if v is None else v
    try:
        v = row[key]
        return default if v is None else v
    except Exception:
        return default


# ----------------------------
# DB Adapter
# ----------------------------
class DB:
    """
    Adapter so the rest of your code can keep doing:
      db = get_db()
      db.execute(...)
      db.commit()
      db.close()

    It auto-converts:
      - SQLite placeholders '?' -> Postgres '%s'
      - SQLite INSERT OR IGNORE -> Postgres ON CONFLICT DO NOTHING

    Plus a safety net:
      - If SQLite ever hits "no such table", we auto-create schema once and retry.
        (This prevents production errors when a new empty DB file is created.)
    """

    def __init__(self, kind: str, conn):
        self.kind = kind
        self.conn = conn

    def _fix_sql(self, sql: str) -> str:
        if self.kind != "postgres":
            return sql

        # 1) placeholders
        sql = sql.replace("?", "%s")

        # 2) Convert INSERT OR IGNORE to ON CONFLICT DO NOTHING
        if "INSERT OR IGNORE INTO" in sql:
            sql = sql.replace("INSERT OR IGNORE INTO", "INSERT INTO")
            sql = sql.strip().rstrip(";")
            sql += " ON CONFLICT DO NOTHING"

        return sql

    def execute(self, sql: str, params=None):
        sql_fixed = self._fix_sql(sql)
        params = params or ()

        cur = self.conn.cursor()
        try:
            cur.execute(sql_fixed, params)
            return cur
        except sqlite3.OperationalError as e:
            # Only for SQLite, and only for missing tables. Don't intercept schema creation itself.
            msg = str(e).lower()
            is_create = sql_fixed.lstrip().upper().startswith(("CREATE TABLE", "PRAGMA", "BEGIN", "COMMIT"))
            if self.kind == "sqlite" and (not is_create) and ("no such table" in msg):
                # Create schema + retry once
                try:
                    ensure_schema(self)
                except Exception:
                    # If schema creation fails, raise original
                    raise

                cur = self.conn.cursor()
                cur.execute(sql_fixed, params)
                return cur

            raise

    def commit(self):
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def _connect_sqlite() -> DB:
    path = _sqlite_db_path()

    # Ensure directory exists (useful if DATABASE points into a folder)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass

    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return DB("sqlite", conn)


def _connect_postgres() -> DB:
    db_url = os.environ["DATABASE_URL"]
    conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)
    return DB("postgres", conn)


# ----------------------------
# Schema guards (NEW)
# ----------------------------
def _sqlite_table_exists(db: DB, table_name: str) -> bool:
    try:
        cur = db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (table_name,),
        )
        return cur.fetchone() is not None
    except Exception:
        return False


def _postgres_table_exists(db: DB, table_name: str) -> bool:
    try:
        cur = db.execute(
            """
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema='public' AND table_name=%s
            LIMIT 1
            """,
            (table_name,),
        )
        return cur.fetchone() is not None
    except Exception:
        return False


def schema_ready(db: DB) -> bool:
    """
    True if core tables exist.
    """
    if db.kind == "postgres":
        return _postgres_table_exists(db, "users") and _postgres_table_exists(db, "events")
    return _sqlite_table_exists(db, "users") and _sqlite_table_exists(db, "events")


def ensure_schema(db: DB):
    """
    Ensure schema exists for the current DB connection.
    Safe to call many times.
    """
    if schema_ready(db):
        return

    if db.kind == "postgres":
        _create_schema_postgres(db)
    else:
        _create_schema_sqlite(db)


# ----------------------------
# Flask DB access
# ----------------------------
def get_db() -> DB:
    """
    Returns a request-scoped DB connection (stored on flask.g).

    Key fix:
    - After connecting, ensure_schema() runs once per request context.
      This prevents "sqlite3.OperationalError: no such table: events" even if
      Render created a fresh empty SQLite file.
    """
    if not hasattr(g, "db") or g.db is None:
        g.db = _connect_postgres() if using_postgres() else _connect_sqlite()

    if not getattr(g, "_schema_checked", False):
        try:
            ensure_schema(g.db)
        finally:
            g._schema_checked = True

    return g.db


def close_db(e=None):
    db = getattr(g, "db", None)
    if db is not None:
        db.close()
        g.db = None


# ----------------------------
# Schema Introspection
# ----------------------------
def get_table_columns(db: DB, table_name: str) -> Set[str]:
    """
    Returns a set of column names for a table.
    Works for both SQLite and Postgres.
    """
    cols: Set[str] = set()

    if db.kind == "postgres":
        cur = db.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema='public' AND table_name=%s
            """,
            (table_name,),
        )
        rows = cur.fetchall() or []
        for r in rows:
            cols.add(r["column_name"] if isinstance(r, dict) else r[0])
        return cols

    cur = db.execute(f"PRAGMA table_info({table_name})")
    rows = cur.fetchall() or []
    for r in rows:
        cols.add(r["name"] if isinstance(r, dict) else r[1])
    return cols


# ----------------------------
# Schema creation
# ----------------------------
def _create_schema_sqlite(db: DB):
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
        );
        """
    )

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
        );
        """
    )

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
        );
        """
    )

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
        );
        """
    )

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
        );
        """
    )

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
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS photos_day_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL UNIQUE,
            token TEXT NOT NULL DEFAULT '',
            is_open INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )


        db.execute(

            """

            CREATE TABLE IF NOT EXISTS otps (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                user_id INTEGER NOT NULL,

                otp_code TEXT NOT NULL,

                purpose TEXT NOT NULL,

                expires_at TEXT NOT NULL,

                created_at TEXT NOT NULL,

                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE

            );

            """

        )


        db.execute(

            """

            CREATE TABLE IF NOT EXISTS audit_logs (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                user_id INTEGER,

                event TEXT NOT NULL,

                ip_address TEXT NOT NULL,

                created_at TEXT NOT NULL DEFAULT '',

                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL

            );

            """

        )

    db.commit()


def _create_schema_postgres(db: DB):
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
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
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            slug TEXT UNIQUE NOT NULL,

            name TEXT NOT NULL,
            date_iso TEXT NOT NULL,
            location TEXT NOT NULL,
            description TEXT NOT NULL,

            passcode TEXT NOT NULL,
            owner_user_id BIGINT,

            cover_image TEXT DEFAULT '',
            created_at TEXT DEFAULT '',

            CONSTRAINT fk_events_owner
              FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS sections (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL,
            section_key TEXT NOT NULL,

            title TEXT DEFAULT '',
            visible INTEGER DEFAULT 1,

            content TEXT DEFAULT '',
            draft_content TEXT DEFAULT '',

            image TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,

            CONSTRAINT uq_sections_event_key UNIQUE(event_id, section_key),
            CONSTRAINT fk_sections_event
              FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS rsvp_questions (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL,
            position INTEGER NOT NULL DEFAULT 1,
            question TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'main',
            type TEXT NOT NULL DEFAULT 'text',
            allow_multi INTEGER NOT NULL DEFAULT 0,
            options TEXT NOT NULL DEFAULT '[]',
            required INTEGER NOT NULL DEFAULT 1,
            show_if_question BIGINT,
            show_if_value TEXT NOT NULL DEFAULT '',
            CONSTRAINT fk_rsvp_questions_event
              FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS rsvp_responses (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL,
            user_id BIGINT,

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

            CONSTRAINT fk_rsvp_responses_event
              FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
            CONSTRAINT fk_rsvp_responses_user
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS event_photos (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL,
            kind TEXT NOT NULL,
            file_name TEXT NOT NULL,
            uploader_user_id BIGINT,
            uploader_name TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            CONSTRAINT fk_event_photos_event
              FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
            CONSTRAINT fk_event_photos_user
              FOREIGN KEY(uploader_user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS photos_day_settings (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL UNIQUE,
            token TEXT NOT NULL DEFAULT '',
            is_open INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT '',
            CONSTRAINT fk_photos_day_settings_event
              FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_otps (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user_id BIGINT NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT fk_password_reset_otps_user
              FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )

    db.commit()


def init_db():
    """
    Idempotent schema init + defaults.
    Safe to call at startup and/or during requests.
    """
    db = get_db()
    ensure_schema(db)

    ensure_default_admin()
    ensure_default_sections_for_all_events()


# ----------------------------
# Default admin
# ----------------------------
def ensure_default_admin():
    db = get_db()
    ensure_schema(db)

    default_email = os.getenv("DEFAULT_ADMIN_EMAIL", "dehindeaba@gmail.com")
    default_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin1234")

    cur = db.execute("SELECT id FROM users WHERE email=?", (default_email,))
    row = cur.fetchone()
    if row:
        return

    pwd_hash = generate_password_hash(default_password)
    cols = get_table_columns(db, "users")

    if "is_verified" in cols and "failed_login_attempts" in cols:
        db.execute(
            """
            INSERT INTO users
              (email, password_hash, role, is_verified, failed_login_attempts, is_locked,
               otp_hash, otp_expires_at, otp_purpose, created_at)
            VALUES
              (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                default_email,
                pwd_hash,
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
    else:
        db.execute(
            "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (default_email, pwd_hash, "admin", now_iso()),
        )

    db.commit()


# ----------------------------
# Default sections
# ----------------------------
DEFAULT_SECTIONS = [
    ("home", "Home", 10, ""),
    ("story", "Our Story", 20, ""),
    ("meet-couple", "Meet the Couple", 30, ""),
    ("proposal", "The Proposal", 40, ""),
    ("tidbits", "Tidbits", 50, "[]"),
    ("qa", "Q&A", 60, "[]"),
    ("rsvp", "RSVP", 70, ""),
    ("photos", "Photos", 80, ""),
    ("photos-day", "Photos of the Day", 90, ""),
]


def ensure_default_sections(event_id: int):
    db = get_db()
    ensure_schema(db)

    cols = get_table_columns(db, "sections")

    # Real schema
    if "title" in cols and "content" in cols and "section_key" in cols:
        for (key, title, sort_order, initial_content) in DEFAULT_SECTIONS:
            db.execute(
                "INSERT OR IGNORE INTO sections "
                "(event_id, section_key, title, visible, content, draft_content, image, sort_order) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (int(event_id), key, title, 1, initial_content, initial_content, "", int(sort_order)),
            )
        db.commit()
        return

    # Old schema fallback
    for (key, title, _, initial_content) in DEFAULT_SECTIONS:
        if "created_at" in cols:
            db.execute(
                "INSERT OR IGNORE INTO sections (event_id, section_key, section_title, section_content, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (int(event_id), key, title, initial_content, now_iso()),
            )
        else:
            db.execute(
                "INSERT OR IGNORE INTO sections (event_id, section_key, section_title, section_content) "
                "VALUES (?, ?, ?, ?)",
                (int(event_id), key, title, initial_content),
            )
    db.commit()


def ensure_default_sections_for_all_events():
    db = get_db()
    ensure_schema(db)

    cur = db.execute("SELECT id FROM events", ())
    rows = cur.fetchall() or []
    for r in rows:
        event_id = row_get(r, "id")
        if event_id is not None:
            ensure_default_sections(int(event_id))


# ----------------------------
# Flask integration (optional)
# ----------------------------
def init_app(app):
    """
    If you prefer, call this from app.py instead of manually calling init_db().
      from db_core import init_app
      init_app(app)
    """
    app.config.setdefault("DATABASE", os.path.abspath(os.getenv("DATABASE_PATH", "app.db")))
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()
