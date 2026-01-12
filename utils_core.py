# utils_core.py
"""
Shared utilities (slugging, sanitization, OTP helpers, access checks, audit logging, etc.)

UPDATED:
- Uses the unified DB adapter from db_core.py (works on Postgres; placeholders stay `?`)
- OTP helpers use users.otp_hash/users.otp_expires_at/users.otp_purpose (NOT legacy otps table)
- Sanitizer is safer + supports <img> (matches your editors / events_routes needs)
- Uses timezone-aware UTC everywhere
"""

import os
import re
import json
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from werkzeug.security import generate_password_hash, check_password_hash

# IMPORTANT: Use SAME DB layer everywhere
from db_core import get_db, row_get, now_iso


# ================= JSON HELPERS =================

def parse_qa_list_json(raw: str) -> List[Dict[str, str]]:
    """
    Safely parse a JSON-encoded Q&A / Tidbits list.

    Supports BOTH formats:
      [{"q":"..","a":".."}]
      [{"question":"..","answer":".."}]

    Always returns:
      [{"q": "...", "a": "..."}]
    """
    if not raw:
        return []

    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            return []

        cleaned: List[Dict[str, str]] = []
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
    Generate a unique slug in the current DB (Postgres).

    NOTE: Keep `?` placeholders; db_core converts them to `%s` for Postgres.
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
            return slug
        i += 1
        slug = f"{base}-{i}"


# ================= HTML SANITIZATION =================

def sanitize_quill_html(html: str) -> str:
    """
    Safer sanitizer for Quill/editor HTML.

    Behavior:
    - strips script/style/iframe blocks
    - strips inline event handlers (onclick, onload, etc.)
    - blocks javascript: URLs in href/src
    - allowlist tags: p, br, strong, em, u, s, ul, ol, li, h1-h4, blockquote, code, pre, a, img, span, div
    """
    html = (html or "").strip()
    if not html:
        return ""

    # Remove dangerous blocks entirely
    html = re.sub(
        r"<\s*(script|style|iframe)\b[^>]*>.*?<\s*/\s*\1\s*>",
        "",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Remove inline event handlers like onclick="..." / onclick='...' / onclick=unquoted
    html = re.sub(r'\son\w+\s*=\s*"[^"]*"', "", html, flags=re.IGNORECASE)
    html = re.sub(r"\son\w+\s*=\s*'[^']*'", "", html, flags=re.IGNORECASE)
    html = re.sub(r"\son\w+\s*=\s*[^\s>]+", "", html, flags=re.IGNORECASE)

    # Block javascript: in href/src (double-quoted, single-quoted, and best-effort unquoted)
    html = re.sub(r'href\s*=\s*"(javascript:[^"]*)"', 'href="#"', html, flags=re.IGNORECASE)
    html = re.sub(r"href\s*=\s*'(javascript:[^']*)'", "href='#'", html, flags=re.IGNORECASE)
    html = re.sub(r'href\s*=\s*(javascript:[^\s>]+)', 'href="#"', html, flags=re.IGNORECASE)

    html = re.sub(r'src\s*=\s*"(javascript:[^"]*)"', 'src=""', html, flags=re.IGNORECASE)
    html = re.sub(r"src\s*=\s*'(javascript:[^']*)'", "src=''", html, flags=re.IGNORECASE)
    html = re.sub(r"src\s*=\s*(javascript:[^\s>]+)", 'src=""', html, flags=re.IGNORECASE)

    # Allow only selected tags (keeps attributes on allowed tags)
    allowed = "p|br|strong|em|u|s|ul|ol|li|h1|h2|h3|h4|blockquote|code|pre|a|img|span|div"

    # Remove any tag not in allowlist (keeps inner text)
    html = re.sub(
        rf"</?(?!({allowed})\b)[a-zA-Z0-9]+[^>]*>",
        "",
        html,
        flags=re.IGNORECASE,
    )

    # Force safe link attrs on <a ...>
    def _fix_a(m: re.Match) -> str:
        tag = m.group(0)

        if re.search(r"\btarget\s*=", tag, flags=re.IGNORECASE) is None:
            tag = tag[:-1] + ' target="_blank">'  # add before >
        if re.search(r"\brel\s*=", tag, flags=re.IGNORECASE) is None:
            tag = tag[:-1] + ' rel="noopener noreferrer">'  # add before >
        return tag

    html = re.sub(r"<a\b[^>]*>", _fix_a, html, flags=re.IGNORECASE)

    return html


# ================= PASSWORD POLICY =================

MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", "8"))


def validate_password_policy(password: str) -> Tuple[bool, Optional[str]]:
    password = password or ""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if " " in password:
        return False, "Password must not contain spaces."
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must include at least one letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\\[\]]", password):
        return False, "Password must include at least one special character."
    return True, None


# ================= OTP HELPERS (UPDATED: users table) =================

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


def set_user_otp(user_id: int, purpose: str = "verify", expires: int = 15) -> str:
    """
    Stores OTP on users table:
      users.otp_hash
      users.otp_expires_at
      users.otp_purpose
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


def verify_user_otp(user_id: int, otp: str, purpose: str = "verify") -> bool:
    """
    Verifies OTP against users table fields.
    """
    otp = (otp or "").strip()
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
    if not otp_hash:
        return False

    try:
        ok = check_password_hash(otp_hash, otp)
    except Exception:
        ok = False

    return bool(ok)


def can_resend_otp(user_id: int, purpose: str, cooldown: int = 60) -> bool:
    """
    Cooldown check using users.otp_expires_at.
    Approximation: last_sent = expires_at - 15 minutes.
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

        last_sent = expires_at - timedelta(minutes=15)
        return (datetime.now(timezone.utc) - last_sent).total_seconds() >= int(cooldown)
    except Exception:
        return True


#===========================================================================================

def has_event_access(event_row: Any, user_row: Any = None) -> bool:
    """
    Determine if a user has access to an event.

    Supports:
    - is_public (optional)
    - owner_user_id (new) OR user_id (legacy)
    """
    if not event_row:
        return False

    is_public = row_get(event_row, "is_public", None)
    if is_public is not None:
        try:
            if int(is_public or 0) == 1:
                return True
        except Exception:
            pass

    if not user_row:
        return False

    user_id = row_get(user_row, "id")
    owner_id = row_get(event_row, "owner_user_id", None)
    if owner_id is None:
        owner_id = row_get(event_row, "user_id", None)

    try:
        if user_id and owner_id and int(user_id) == int(owner_id):
            return True
    except Exception:
        pass

    if (row_get(user_row, "role") or "").lower() == "admin":
        return True

    return False


def event_session_key(event_id: int) -> str:
    return f"event_{int(event_id)}"


def ensure_photos_day_token(session_obj: Any, prefix: str = "photos_day") -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"{prefix}_{today}"

    token = session_obj.get(key)
    if token:
        return token

    token = secrets.token_urlsafe(12)
    session_obj[key] = token
    return token


def log_security_event(user_id: Optional[int], event: str, ip: str) -> None:
    """
    Best-effort audit logging. Won't crash if table/columns differ.
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
        # If audit_logs doesn't exist or schema differs, don't break flows
        pass
