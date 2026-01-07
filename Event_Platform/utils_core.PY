import sqlite3
import os
import re
import secrets
import string
from datetime import datetime, timedelta
from html import escape


DATABASE = "app.db"


import json

def parse_qa_list_json(raw: str):
    """
    Safely parse a JSON-encoded Q&A / Tidbits list.

    Supports BOTH formats:
      [{"q":"..","a":".."}]
      [{"question":"..","answer":".."}]

    Always returns a list of dicts shaped like:
      [{"q": "...", "a": "..."}]
    """
    if not raw:
        return []

    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            return []

        cleaned = []
        for item in data:
            if not isinstance(item, dict):
                continue

            q = (item.get("q") or item.get("question") or "").strip()
            a = (item.get("a") or item.get("answer") or "").strip()

            # Keep items that have either question or answer text
            if q or a:
                cleaned.append({"q": q, "a": a})

        return cleaned

    except Exception:
        return []









# ================= DATABASE =================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def row_get(row, key, default=None):
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


# ================= STRING / SLUG HELPERS =================

def slugify(text: str) -> str:
    text = (text or "").strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text)
    text = re.sub(r"^-+|-+$", "", text)
    return text


def unique_slug(base_text: str, table: str = "events", column: str = "slug") -> str:
    base = slugify(base_text)
    slug = base
    db = get_db()
    i = 1

    while True:
        row = db.execute(
            f"SELECT 1 FROM {table} WHERE {column}=? LIMIT 1",
            (slug,),
        ).fetchone()
        if not row:
            break
        i += 1
        slug = f"{base}-{i}"

    db.close()
    return slug


# ================= HTML SANITIZATION =================

def sanitize_quill_html(html: str) -> str:
    if not html:
        return ""

    html = re.sub(
        r"<\s*(script|style|iframe).*?>.*?<\s*/\s*\1\s*>",
        "",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    escaped = escape(html)

    allowed_tags = {
        "p", "br", "strong", "em", "u", "s",
        "ul", "ol", "li",
        "h1", "h2", "h3", "h4",
        "blockquote", "code", "pre",
        "a",
    }

    for tag in allowed_tags:
        escaped = re.sub(fr"&lt;{tag}&gt;", f"<{tag}>", escaped, flags=re.I)
        escaped = re.sub(fr"&lt;/{tag}&gt;", f"</{tag}>", escaped, flags=re.I)

    escaped = re.sub(
        r'<a[^>]*href="([^"]+)"[^>]*>',
        lambda m: f'<a href="{m.group(1)}" target="_blank" rel="noopener noreferrer">',
        escaped,
        flags=re.I,
    )

    return escaped


# ================= PASSWORD POLICY =================

MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", 8))

def validate_password_policy(password: str):
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if " " in password:
        return False, "Password must not contain spaces."
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must include at least one letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\]]", password):
        return False, "Password must include at least one special character."
    return True, None


# ================= OTP HELPERS =================

def generate_otp():
    return "".join(secrets.choice(string.digits) for _ in range(6))


def set_user_otp(user_id, purpose, expires=15):
    otp = generate_otp()
    expiry = datetime.utcnow() + timedelta(minutes=expires)

    db = get_db()
    db.execute(
        """
        INSERT INTO otps (user_id, otp_code, purpose, expires_at, created_at)
        VALUES (?,?,?,?,?)
        """,
        (user_id, otp, purpose, expiry.isoformat(), datetime.utcnow().isoformat()),
    )
    db.commit()
    db.close()
    return otp


def verify_user_otp(user_id, otp, purpose):
    db = get_db()
    row = db.execute(
        """
        SELECT 1 FROM otps
        WHERE user_id=? AND otp_code=? AND purpose=? AND expires_at > ?
        """,
        (user_id, otp, purpose, datetime.utcnow().isoformat()),
    ).fetchone()
    db.close()
    return row is not None


def can_resend_otp(user_id, purpose, cooldown=60):
    db = get_db()
    row = db.execute(
        """
        SELECT created_at FROM otps
        WHERE user_id=? AND purpose=?
        ORDER BY id DESC LIMIT 1
        """,
        (user_id, purpose),
    ).fetchone()
    db.close()

    if not row:
        return True

    return (datetime.utcnow() - datetime.fromisoformat(row["created_at"])).seconds >= cooldown




#===========================================================================================

def has_event_access(event_row, user_row=None):
    """
    Determine if a user has access to an event.

    Rules:
    - Public events are always accessible
    - Event owner always has access
    - Admin users always have access
    """
    if not event_row:
        return False

    # Public event
    if int(row_get(event_row, "is_public", 1) or 1) == 1:
        return True

    # No user -> no access to private event
    if not user_row:
        return False

    user_id = row_get(user_row, "id")
    owner_id = row_get(event_row, "user_id")

    # Owner access
    if user_id and owner_id and int(user_id) == int(owner_id):
        return True

    # Admin access
    if (row_get(user_row, "role") or "").lower() == "admin":
        return True

    return False

#============================================================================================
def event_session_key(event_id):
    """
    Generate a consistent session key for an event.

    Example:
      event_id = 42
      -> 'event_42'
    """
    return f"event_{int(event_id)}"

#=====================================================================================

def now_iso():
    """UTC now as ISO string."""
    return datetime.utcnow().isoformat()


def ensure_photos_day_token(session_obj, prefix="photos_day"):
    """
    Ensure there is a stable per-day token stored in session.
    Returns the token string.

    Typical usage:
      token = ensure_photos_day_token(session)
    """
    today = datetime.utcnow().strftime("%Y-%m-%d")
    key = f"{prefix}_{today}"

    token = session_obj.get(key)
    if token:
        return token

    token = secrets.token_urlsafe(12)
    session_obj[key] = token
    return token


# ================= AUDIT LOGGING =================

def log_security_event(user_id, event, ip):
    db = get_db()
    db.execute(
        """
        INSERT INTO audit_logs (user_id, event, ip_address)
        VALUES (?,?,?)
        """,
        (user_id, event, ip),
    )
    db.commit()
    db.close()
