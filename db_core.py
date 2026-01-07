# db_core.py
import os
import sqlite3
from datetime import datetime, timezone

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
    # Prefer Flask config, fallback to env var, fallback to app.db
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
        return row.get(key, default)
    try:
        return row[key]
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
      - SQLite INSERT OR IGNORE -> Postgres ON CONFLICT DO NOTHING (when possible)
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
        # We only do this when the query is exactly INSERT OR IGNORE INTO <table> (...)
        # because Postgres doesn't support OR IGNORE.
        if "INSERT OR IGNORE INTO" in sql:
            # Convert to normal INSERT INTO ...
            sql = sql.replace("INSERT OR IGNORE INTO", "INSERT INTO")

            # Add a generic ON CONFLICT DO NOTHING at the end (works if table has a constraint)
            sql = sql.strip().rstrip(";")
            sql += " ON CONFLICT DO NOTHING"

        return sql

    def execute(self, sql: str, params=None):
        sql = self._fix_sql(sql)
        params = params or ()
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def _connect_sqlite() -> DB:
    path = _sqlite_db_path()
    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return DB("sqlite", conn)


def _connect_postgres() -> DB:
    db_url = os.environ["DATABASE_URL"]
    # RealDictCursor => dict rows
    conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)
    return DB("postgres", conn)


def get_db() -> DB:
    if not hasattr(g, "db") or g.db is None:
        g.db = _connect_postgres() if using_postgres() else _connect_sqlite()
    return g.db


def close_db(e=None):
    db = getattr(g, "db", None)
    if db is not None:
        db.close()
        g.db = None


# ----------------------------
# Schema Introspection
# ----------------------------
def get_table_columns(db: DB, table_name: str) -> set[str]:
    """
    Returns a set of column names for a table.
    Works for both SQLite and Postgres.
    """
    cols = set()

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

    # sqlite
    cur = db.execute(f"PRAGMA table_info({table_name})")
    rows = cur.fetchall() or []
    for r in rows:
        # pragma table_info returns: (cid, name, type, notnull, dflt_value, pk)
        cols.add(r["name"] if isinstance(r, dict) else r[1])
    return cols


# ----------------------------
# Schema creation (matches your REAL imported schema)
# ----------------------------
def _create_schema_sqlite(db: DB):
    """
    This matches the schema you showed from your SQLite dump:
    users, events, sections, rsvp_questions, rsvp_responses,
    event_photos, photos_day_settings, password_reset_otps.
    """
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

    db.commit()


def _create_schema_postgres(db: DB):
    """
    Same schema as SQLite, but Postgres-friendly.
    Uses IF NOT EXISTS so it won't break if you imported already.
    """
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
    db = get_db()
    if db.kind == "postgres":
        _create_schema_postgres(db)
    else:
        _create_schema_sqlite(db)

    ensure_default_admin()
    ensure_default_sections_for_all_events()


# ----------------------------
# Default admin
# ----------------------------
def ensure_default_admin():
    db = get_db()

    default_email = os.getenv("DEFAULT_ADMIN_EMAIL", "dehindeaba@gmail.com")
    default_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin1234")

    # already exists?
    cur = db.execute("SELECT id FROM users WHERE email=?", (default_email,))
    row = cur.fetchone()
    if row:
        return

    pwd_hash = generate_password_hash(default_password)
    cols = get_table_columns(db, "users")

    # NEW/REAL schema (from your dump)
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
        # Older/simpler schema fallback
        db.execute(
            "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (default_email, pwd_hash, "admin", now_iso()),
        )

    db.commit()


# ----------------------------
# Default sections
# ----------------------------
def ensure_default_sections(event_id: int):
    """
    Inserts default sections IF they are missing.
    Works with both:
      - Real schema: title/visible/content/draft_content/image/sort_order
      - Old schema: section_title/section_content/created_at
    """
    db = get_db()
    cols = get_table_columns(db, "sections")

    defaults = [
        ("agenda", "Agenda", ""),
        ("speakers", "Speakers", ""),
        ("notes", "Notes", ""),
    ]

    # Real schema
    if "title" in cols and "content" in cols:
        # best effort: include visible/draft_content/image/sort_order if present
        for i, (key, title, content) in enumerate(defaults, start=1):
            visible = 1
            draft_content = ""
            image = ""
            sort_order = 1000 + i * 10

            # Use INSERT OR IGNORE for SQLite; auto converts for Postgres adapter.
            db.execute(
                "INSERT OR IGNORE INTO sections "
                "(event_id, section_key, title, visible, content, draft_content, image, sort_order) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (event_id, key, title, visible, content, draft_content, image, sort_order),
            )
        db.commit()
        return

    # Old schema fallback
    for key, title, content in defaults:
        if "created_at" in cols:
            db.execute(
                "INSERT OR IGNORE INTO sections (event_id, section_key, section_title, section_content, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (event_id, key, title, content, now_iso()),
            )
        else:
            db.execute(
                "INSERT OR IGNORE INTO sections (event_id, section_key, section_title, section_content) "
                "VALUES (?, ?, ?, ?)",
                (event_id, key, title, content),
            )
    db.commit()


def ensure_default_sections_for_all_events():
    db = get_db()
    cur = db.execute("SELECT id FROM events", ())
    rows = cur.fetchall() or []
    for r in rows:
        event_id = row_get(r, "id")
        if event_id is None:
            continue
        ensure_default_sections(int(event_id))


# ----------------------------
# Flask integration
# ----------------------------
def init_app(app):
    # optional: override SQLite file via config
    app.config.setdefault("DATABASE", os.path.abspath(os.getenv("DATABASE_PATH", "app.db")))
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()
