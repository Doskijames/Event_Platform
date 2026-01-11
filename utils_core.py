# utils_core.py
"""
Shared utilities (slugging, sanitization, OTP helpers, etc.)

IMPORTANT CHANGE:
- This module now uses the unified DB adapter from db_core.py so it works with BOTH:
  - SQLite (local dev)
  - Postgres (Render/Neon/Supabase/etc)
"""

import os
import re
import secrets
import string
import json
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Any, Dict, List, Tuple, Optional

from werkzeug.security import generate_password_hash, check_password_hash

# ✅ Unified DB adapter + helpers
from db_core import get_db, row_get, now_iso


# ================= JSON HELPERS =================

def parse_qa_list_json(raw: str) -> List[Dict[str, str]]:
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
    Generates a unique slug for `table.column`.

    Uses db_core.get_db() so it works on Postgres too.

    NOTE:
    - Keep SQLite-style placeholders (?) because db_core.DB converts them to %s on Postgres.
    """
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

    return slug


# ================= HTML SANITIZATION =================

def sanitize_quill_html(html: str) -> str:
    """
    Basic sanitizer for Quill HTML output.

    Removes script/style/iframe blocks and allows a conservative list of tags.
    """
    if not html:
        return ""

    # strip dangerous blocks
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
        "span",
    }

    for tag in allowed_tags:
        escaped = re.sub(fr"&lt;{tag}&gt;", f"<{tag}>", escaped, flags=re.I)
        escaped = re.sub(fr"&lt;/{tag}&gt;", f"</{tag}>", escaped, flags=re.I)

    # allow a[href="..."] but force safe attrs
    escaped = re.sub(
        r'<a[^>]*href="([^"]+)"[^>]*>',
        lambda m: f'<a href="{m.group(1)}" target="_blank" rel="noopener noreferrer">',
        escaped,
        flags=re.I,
    )

    return escaped


# ================= PASSWORD POLICY =================

MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", 8))


def validate_password_policy(password: str) -> Tuple[bool, Optional[str]]:
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

def generate_otp() -> str:
    return "".join(secrets.choice(string.digits) for _ in range(6))


def _parse_iso_dt(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def set_user_otp(user_id: int, purpose: str, expires: int = 15) -> str:
    """
    Stores OTP on the users table using the schema in db_core:
      users.otp_hash
      users.otp_expires_at
      users.otp_purpose

    This avoids requiring a separate 'otps' table.
    """
    otp = generate_otp()
    otp_hash = generate_password_hash(otp)
    expiry = datetime.now(timezone.utc) + timedelta(minutes=int(expires))

    db = get_db()
    db.execute(
        """
        UPDATE users
        SET otp_hash=?, otp_expires_at=?, otp_purpose=?
        WHERE id=?
        """,
        (otp_hash, expiry.isoformat(), (purpose or "verify"), int(user_id)),
    )
    db.commit()
    return otp


def verify_user_otp(user_id: int, otp: str, purpose: str) -> bool:
    """
    Verifies OTP against users table fields.
    """
    if not otp:
        return False

    db = get_db()
    row = db.execute(
        "SELECT otp_hash, otp_expires_at, otp_purpose FROM users WHERE id=?",
        (int(user_id),),
    ).fetchone()

    if not row:
        return False

    stored_purpose = (row_get(row, "otp_purpose") or "").strip()
    if (purpose or "").strip() and stored_purpose and stored_purpose != (purpose or "").strip():
        return False

    expires_at = _parse_iso_dt(row_get(row, "otp_expires_at") or "")
    if not expires_at or expires_at <= datetime.now(timezone.utc):
        return False

    otp_hash = row_get(row, "otp_hash") or ""
    try:
        return check_password_hash(otp_hash, otp)
    except Exception:
        return False


def can_resend_otp(user_id: int, purpose: str, cooldown: int = 60) -> bool:
    """
    Best-effort cooldown check without requiring an extra table.

    We approximate "last sent" as: expires_at - 15 minutes (default window),
    if we can parse expires_at. If not, we allow resend.
    """
    try:
        db = get_db()
        row = db.execute(
            "SELECT otp_expires_at, otp_purpose FROM users WHERE id=?",
            (int(user_id),),
        ).fetchone()
        if not row:
            return True

        stored_purpose = (row_get(row, "otp_purpose") or "").strip()
        if stored_purpose and (purpose or "").strip() and stored_purpose != (purpose or "").strip():
            return True

        expires_at = _parse_iso_dt(row_get(row, "otp_expires_at") or "")
        if not expires_at:
            return True

        # assume default expiry window is 15 minutes; if you change expires defaults,
        # this is just an approximation.
        last_sent = expires_at - timedelta(minutes=15)
        return (datetime.now(timezone.utc) - last_sent).total_seconds() >= int(cooldown)
    except Exception:
        return True


#===========================================================================================

def has_event_access(event_row: Any, user_row: Any = None) -> bool:
    """
    Determine if a user has access to an event.

    Supports multiple legacy schemas:
    - is_public (optional)
    - owner_user_id (db_core) or user_id (legacy)

    If is_public is missing, we assume events are passcode-gated elsewhere.
    """
    if not event_row:
        return False

    # Public event (if column exists)
    is_public = row_get(event_row, "is_public", None)
    if is_public is not None:
        try:
            if int(is_public or 0) == 1:
                return True
        except Exception:
            pass

    # No user -> no access to private event
    if not user_row:
        return False

    user_id = row_get(user_row, "id")
    owner_id = row_get(event_row, "owner_user_id", None)
    if owner_id is None:
        owner_id = row_get(event_row, "user_id", None)

    # Owner access
    try:
        if user_id and owner_id and int(user_id) == int(owner_id):
            return True
    except Exception:
        pass

    # Admin access
    if (row_get(user_row, "role") or "").lower() == "admin":
        return True

    return False


#============================================================================================
def event_session_key(event_id: int) -> str:
    """
    Generate a consistent session key for an event.
    """
    return f"event_{int(event_id)}"


#=====================================================================================

def ensure_photos_day_token(session_obj: Any, prefix: str = "photos_day") -> str:
    """
    Ensure there is a stable per-day token stored in session.
    Returns the token string.
    """
    today = datetime.utcnow().strftime("%Y-%m-%d")
    key = f"{prefix}_{today}"

    token = session_obj.get(key)
    if token:
        return token

    token = secrets.token_urlsafe(12)
    session_obj[key] = token
    return token


# ================= AUDIT LOGGING (best-effort) =================

def log_security_event(user_id: int, event: str, ip: str) -> None:
    """
    Best-effort audit logging.

    If you don't have an audit_logs table, this becomes a no-op (won't crash your app).
    """
    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO audit_logs (user_id, event, ip_address, created_at)
            VALUES (?,?,?,?)
            """,
            (int(user_id) if user_id else None, (event or ""), (ip or ""), now_iso()),
        )
        db.commit()
    except Exception:
        # table may not exist; don't break auth flows
        pass
