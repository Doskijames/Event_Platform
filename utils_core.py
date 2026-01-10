# utils_core.py
import os
import re
import json
import secrets
import string
from datetime import datetime, timedelta, timezone
from html import escape

# IMPORTANT:
#   This project now supports Postgres via db_core.DB adapter.
#   DO NOT open sqlite3 connections directly in this file.
#   Always use db_core.get_db() so your code works for BOTH SQLite and Postgres.
from db_core import get_db, row_get, now_iso


# ================= JSON HELPERS =================

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

            if q or a:
                cleaned.append({"q": q, "a": a})

        return cleaned

    except Exception:
        return []


# ================= STRING / SLUG HELPERS =================

def slugify(text: str) -> str:
    text = (text or "").strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text)
    text = re.sub(r"^-+|-+$", "", text)
    return text


def unique_slug(base_text: str, table: str = "events", column: str = "slug") -> str:
    """
    Generate a unique slug by checking the DB.

    Uses db_core.get_db() so it works on Postgres (Render) AND SQLite (local dev).
    """
    base = slugify(base_text)
    slug = base
    i = 1

    db = get_db()
    try:
        while True:
            row = db.execute(
                f"SELECT 1 FROM {table} WHERE {column}=? LIMIT 1",
                (slug,),
            ).fetchone()
            if not row:
                break
            i += 1
            slug = f"{base}-{i}"
    finally:
        # db_core.get_db() stores connection on flask.g during requests.
        # Closing here is safe for non-request contexts too.
        try:
            db.close()
        except Exception:
            pass

    return slug


# ================= HTML SANITIZATION =================

def sanitize_quill_html(html: str) -> str:
    if not html:
        return ""

    # Drop dangerous blocks entirely
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
        "a", "img",
        "span", "div"
    }

    # Unescape allowed tags (basic)
    for tag in allowed_tags:
        escaped = re.sub(fr"&lt;{tag}(&gt;|\s)", lambda m: f"<{tag}" + (">" if m.group(1)==">" else " "), escaped, flags=re.I)
        escaped = re.sub(fr"&lt;/{tag}&gt;", f"</{tag}>", escaped, flags=re.I)

    # Links: force safe target/rel
    escaped = re.sub(
        r'<a([^>]*?)href="([^"]+)"([^>]*)>',
        lambda m: f'<a{m.group(1)}href="{m.group(2)}"{m.group(3)} target="_blank" rel="noopener noreferrer">',
        escaped,
        flags=re.I,
    )

    # Images: allow src only, prevent javascript: / data: by stripping unsafe sources
    def _fix_img(m):
        attrs = m.group(1) or ""
        # Extract src
        src_match = re.search(r'src="([^"]+)"', attrs, flags=re.I)
        if not src_match:
            return "<img>"
        src = src_match.group(1).strip()
        if src.lower().startswith("javascript:"):
            src = ""
        # allow https/http and your own /static/ or /media/ paths
        if src and not (src.startswith("http://") or src.startswith("https://") or src.startswith("/")):
            src = ""
        return f'<img src="{src}">'

    escaped = re.sub(r"<img([^>]*)>", _fix_img, escaped, flags=re.I)

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
# NOTE: Your db_core schema includes OTP fields on users + password_reset_otps.
# The helpers below use a generic "otps" table. Ensure the table exists in db_core
# (recommended) or refactor your auth to use password_reset_otps consistently.

def generate_otp():
    return "".join(secrets.choice(string.digits) for _ in range(6))


def set_user_otp(user_id, purpose, expires=15):
    otp = generate_otp()
    expiry = datetime.now(timezone.utc) + timedelta(minutes=int(expires))

    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO otps (user_id, otp_code, purpose, expires_at, created_at)
            VALUES (?,?,?,?,?)
            """,
            (int(user_id), otp, str(purpose), expiry.isoformat(), now_iso()),
        )
        db.commit()
    finally:
        try:
            db.close()
        except Exception:
            pass

    return otp


def verify_user_otp(user_id, otp, purpose):
    db = get_db()
    try:
        row = db.execute(
            """
            SELECT 1 FROM otps
            WHERE user_id=? AND otp_code=? AND purpose=? AND expires_at > ?
            """,
            (int(user_id), str(otp), str(purpose), now_iso()),
        ).fetchone()
        return row is not None
    finally:
        try:
            db.close()
        except Exception:
            pass


def can_resend_otp(user_id, purpose, cooldown=60):
    db = get_db()
    try:
        row = db.execute(
            """
            SELECT created_at FROM otps
            WHERE user_id=? AND purpose=?
            ORDER BY id DESC LIMIT 1
            """,
            (int(user_id), str(purpose)),
        ).fetchone()

        if not row:
            return True

        created_raw = row_get(row, "created_at", "") or ""
        try:
            created_dt = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
        except Exception:
            return True

        return (datetime.now(timezone.utc) - created_dt).total_seconds() >= float(cooldown)
    finally:
        try:
            db.close()
        except Exception:
            pass


# ================= ACCESS / SESSION HELPERS =================

def has_event_access(event_row, user_row=None):
    """
    Determine if a user has access to an event.

    Rules:
    - Public events are always accessible (if you add is_public later)
    - Event owner always has access
    - Admin users always have access
    """
    if not event_row:
        return False

    # Default to public if column doesn't exist
    is_public = int(row_get(event_row, "is_public", 1) or 1)
    if is_public == 1:
        return True

    if not user_row:
        return False

    user_id = row_get(user_row, "id")
    owner_id = row_get(event_row, "owner_user_id") or row_get(event_row, "user_id")

    if user_id and owner_id and int(user_id) == int(owner_id):
        return True

    if (row_get(user_row, "role") or "").lower() == "admin":
        return True

    return False


def event_session_key(event_id):
    return f"event_{int(event_id)}"


def ensure_photos_day_token(session_obj, prefix="photos_day"):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
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
    try:
        db.execute(
            """
            INSERT INTO audit_logs (user_id, event, ip_address, created_at)
            VALUES (?,?,?,?)
            """,
            (int(user_id) if user_id else None, str(event), str(ip), now_iso()),
        )
        db.commit()
    finally:
        try:
            db.close()
        except Exception:
            pass
