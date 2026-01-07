import os
import re
import secrets
import smtplib
import random
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta, datetime as dt_cls
from functools import wraps

from flask import (
    render_template, request, redirect, url_for,
    session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

from db_core import get_db


# -------------------- Safe row getter --------------------
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


# -------------------- Config --------------------
PASSWORD_MIN_LEN = int((os.getenv("MIN_PASSWORD_LENGTH") or os.getenv("PASSWORD_MIN_LEN") or "8").strip())
MAX_FAILED_LOGINS = int((os.getenv("MAX_FAILED_LOGINS") or "5").strip())

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int((os.getenv("SMTP_PORT") or "465").strip())
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

OTP_TTL_MINUTES = int((os.getenv("OTP_TTL_MINUTES") or "15").strip())
OTP_SUBJECT_VERIFY = os.getenv("OTP_SUBJECT_VERIFY", "Verify your email (OTP)")
OTP_SUBJECT_UNLOCK = os.getenv("OTP_SUBJECT_UNLOCK", "Unlock your account (OTP)")
OTP_SUBJECT_RESET = os.getenv("OTP_SUBJECT_RESET", "Reset your password (OTP)")

# CAPTCHA settings
CAPTCHA_AFTER_FAILED = int((os.getenv("CAPTCHA_AFTER_FAILED") or "2").strip())
CAPTCHA_TTL_SECONDS = int((os.getenv("CAPTCHA_TTL_SECONDS") or "600").strip())  # 10 mins


def now_utc():
    return datetime.now(timezone.utc)


# -------------------- CAPTCHA helpers --------------------
def _captcha_generate():
    a = random.randint(2, 9)
    b = random.randint(1, 9)
    q = f"{a} + {b}"
    ans = str(a + b)
    return q, ans


def _captcha_set_new():
    q, ans = _captcha_generate()
    session["captcha_required"] = True
    session["captcha_q"] = q
    session["captcha_a"] = ans
    session["captcha_exp"] = int(datetime.now(timezone.utc).timestamp()) + CAPTCHA_TTL_SECONDS
    return q


def _captcha_get_question_if_required():
    if not session.get("captcha_required"):
        return False, None

    exp = session.get("captcha_exp")
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if not exp or now_ts > int(exp):
        q = _captcha_set_new()
        return True, q

    q = session.get("captcha_q")
    if not q:
        q = _captcha_set_new()
    return True, q


def _captcha_clear():
    session.pop("captcha_required", None)
    session.pop("captcha_q", None)
    session.pop("captcha_a", None)
    session.pop("captcha_exp", None)


def _captcha_validate_from_request():
    require, _ = _captcha_get_question_if_required()
    if not require:
        return True

    user_ans = (request.form.get("captcha") or "").strip()
    correct = (session.get("captcha_a") or "").strip()

    if not user_ans or user_ans != correct:
        _captcha_set_new()
        return False

    return True


# -------------------- Auth helpers --------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def is_logged_in():
    return current_user() is not None


def user_is_verified(user_row) -> bool:
    return int(row_get(user_row, "is_verified", 0) or 0) == 1


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            flash("Please log in to continue.")
            return redirect(url_for("login", next=request.path))

        u = current_user()
        allow = {
            "verify_email",
            "resend_otp",
            "logout",
            "login",
            "register",
            "home",
            "index",
            "static",
            "unlock_account",
            "forgot_password",
            "forgot_password_reset",
            "forgot_password_resend",
            "change_password",
        }
        if u and (not user_is_verified(u)) and (request.endpoint not in allow):
            flash("Please verify your email to continue.")
            return redirect(url_for("verify_email"))

        return fn(*args, **kwargs)
    return wrapper


# -------------------- Password policy --------------------
def validate_password(pw: str):
    pw = (pw or "")
    if len(pw) < PASSWORD_MIN_LEN:
        return False, f"Password must be at least {PASSWORD_MIN_LEN} characters."
    if re.search(r"\s", pw):
        return False, "Password must not contain spaces."
    if not re.search(r"[A-Za-z]", pw):
        return False, "Password must contain at least one letter."
    if not re.search(r"[0-9]", pw):
        return False, "Password must contain at least one number."
    if not re.search(r"[^A-Za-z0-9\s]", pw):
        return False, "Password must contain at least one special character."
    return True, ""


def lock_user_account(user_id: int):
    db = get_db()
    db.execute(
        "UPDATE users SET is_locked=1, failed_login_attempts=? WHERE id=?",
        (MAX_FAILED_LOGINS, user_id),
    )
    db.commit()


def reset_failed_logins(user_id: int):
    db = get_db()
    db.execute("UPDATE users SET failed_login_attempts=0 WHERE id=?", (user_id,))
    db.commit()


# -------------------- OTP email helpers --------------------
def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def send_otp_email(to_email: str, otp: str, purpose: str) -> bool:
    if not all([SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD]):
        print("⚠️ SMTP not configured. OTP not sent.")
        return False

    try:
        msg = EmailMessage()
        subj = OTP_SUBJECT_UNLOCK
        if purpose == "verify":
            subj = OTP_SUBJECT_VERIFY
        elif purpose == "reset":
            subj = OTP_SUBJECT_RESET

        msg["Subject"] = subj
        msg["From"] = SMTP_USER
        msg["To"] = to_email
        msg.set_content(
            f"Your OTP is: {otp}\n\nThis code expires in {OTP_TTL_MINUTES} minutes.\n"
        )

        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        return True
    except Exception as e:
        print("❌ Failed to send OTP email:", repr(e))
        return False


def set_user_otp(user_id: int, purpose: str = "verify", ttl_minutes: int = OTP_TTL_MINUTES):
    otp = generate_otp()
    otp_hash = generate_password_hash(otp)
    expires_at = (now_utc() + timedelta(minutes=ttl_minutes)).isoformat()

    db = get_db()
    db.execute(
        "UPDATE users SET otp_hash=?, otp_expires_at=?, otp_purpose=? WHERE id=?",
        (otp_hash, expires_at, purpose, user_id),
    )
    db.commit()
    return otp


def verify_user_otp(user_id: int, otp: str, purpose: str | None = None) -> bool:
    otp = (otp or "").strip()
    if not otp:
        return False

    db = get_db()
    u = db.execute(
        "SELECT otp_hash, otp_expires_at, otp_purpose FROM users WHERE id=?",
        (user_id,),
    ).fetchone()
    if not u:
        return False

    if purpose and (row_get(u, "otp_purpose", "") or "") != purpose:
        return False

    expires = row_get(u, "otp_expires_at", "") or ""
    if not expires:
        return False

    try:
        exp_dt = dt_cls.fromisoformat(expires)
    except Exception:
        return False

    if exp_dt.tzinfo is None:
        exp_dt = exp_dt.replace(tzinfo=timezone.utc)

    if exp_dt < now_utc():
        return False

    otp_hash = row_get(u, "otp_hash", "") or ""
    if not otp_hash or not check_password_hash(otp_hash, otp):
        return False

    db.execute(
        "UPDATE users SET otp_hash='', otp_expires_at='', otp_purpose='verify' WHERE id=?",
        (user_id,),
    )
    db.commit()
    return True


# -------------------- Forgot password OTP table --------------------
def _ensure_forgot_pw_table(db):
    """
    IMPORTANT:
    - SQLite supports: AUTOINCREMENT
    - Postgres does NOT support AUTOINCREMENT
    This function creates the table with the right syntax depending on db.kind.
    """
    if getattr(db, "kind", "") == "postgres":
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_otps (
              id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
              user_id BIGINT NOT NULL,
              otp_hash TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
    else:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_otps (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              otp_hash TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
    db.commit()


def _issue_forgot_pw_otp(user_id: int) -> str:
    db = get_db()
    _ensure_forgot_pw_table(db)

    db.execute("DELETE FROM password_reset_otps WHERE user_id=?", (int(user_id),))

    otp = f"{secrets.randbelow(1_000_000):06d}"
    otp_hash = generate_password_hash(otp)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=OTP_TTL_MINUTES)).isoformat()
    created = datetime.now(timezone.utc).isoformat()

    db.execute(
        "INSERT INTO password_reset_otps(user_id, otp_hash, expires_at, created_at) VALUES (?,?,?,?)",
        (int(user_id), otp_hash, expires, created),
    )
    db.commit()
    return otp


def _get_forgot_pw_row(user_id: int):
    db = get_db()
    _ensure_forgot_pw_table(db)
    return db.execute(
        "SELECT otp_hash, expires_at FROM password_reset_otps WHERE user_id=? ORDER BY id DESC LIMIT 1",
        (int(user_id),),
    ).fetchone()


def _clear_forgot_pw_otps(user_id: int):
    db = get_db()
    _ensure_forgot_pw_table(db)
    db.execute("DELETE FROM password_reset_otps WHERE user_id=?", (int(user_id),))
    db.commit()


# -------------------- Routes registration --------------------
def register_auth_routes(app):

    # ---------- REGISTER ----------
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""

            if not email:
                flash("Email is required.")
                return render_template("auth_register.html", user=current_user())

            ok, msg = validate_password(password)
            if not ok:
                flash(msg)
                return render_template("auth_register.html", user=current_user())

            db = get_db()
            existing = db.execute("SELECT id FROM users WHERE lower(email)=?", (email,)).fetchone()
            if existing:
                flash("An account with that email already exists. Please log in.")
                return redirect(url_for("login"))

            # Create user (unverified by default)
            pw_hash = generate_password_hash(password)
            db.execute(
                """
                INSERT INTO users (email, password_hash, is_verified, is_locked, failed_login_attempts, otp_hash, otp_expires_at, otp_purpose)
                VALUES (?, ?, 0, 0, 0, '', '', 'verify')
                """,
                (email, pw_hash),
            )
            db.commit()

            new_user = db.execute("SELECT id, email FROM users WHERE lower(email)=?", (email,)).fetchone()
            user_id = int(row_get(new_user, "id"))

            # Send verification OTP
            otp = set_user_otp(user_id, purpose="verify")
            sent = send_otp_email(email, otp, purpose="verify")
            session["verify_user_id"] = user_id

            if sent:
                flash("Account created ✅ We sent an OTP to your email to verify your account.")
            else:
                flash("Account created, but we could not send the OTP email. Please check SMTP settings.")

            return redirect(url_for("verify_email"))

        return render_template("auth_register.html", user=current_user())

    # ---------- LOGIN ----------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            require_captcha, captcha_q = _captcha_get_question_if_required()
            return render_template(
                "auth_login.html",
                user=current_user(),
                require_captcha=require_captcha,
                captcha_q=captcha_q
            )

        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        db = get_db()
        u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not u:
            if session.get("captcha_required"):
                ok = _captcha_validate_from_request()
                if not ok:
                    flash("CAPTCHA incorrect. Please try again.")
                    require_captcha, captcha_q = _captcha_get_question_if_required()
                    return render_template("auth_login.html", user=current_user(), require_captcha=require_captcha, captcha_q=captcha_q)

            flash("Invalid email or password.")
            return redirect(url_for("login"))

        attempts_so_far = int(row_get(u, "failed_login_attempts", 0) or 0)
        if attempts_so_far >= CAPTCHA_AFTER_FAILED:
            session["captcha_required"] = True
            require_captcha, captcha_q = _captcha_get_question_if_required()
            if not require_captcha:
                captcha_q = _captcha_set_new()
                require_captcha = True

            if not _captcha_validate_from_request():
                flash("CAPTCHA incorrect. Please try again.")
                require_captcha, captcha_q = _captcha_get_question_if_required()
                return render_template("auth_login.html", user=current_user(), require_captcha=require_captcha, captcha_q=captcha_q)

        if int(row_get(u, "is_locked", 0) or 0) == 1:
            session["unlock_user_id"] = row_get(u, "id")
            flash("Your account is locked. Enter the OTP we emailed you to unlock it.")
            return redirect(url_for("unlock_account"))

        if not check_password_hash(row_get(u, "password_hash", "") or "", password):
            attempts = attempts_so_far + 1
            if attempts >= CAPTCHA_AFTER_FAILED:
                session["captcha_required"] = True
                _captcha_get_question_if_required()

            if attempts >= MAX_FAILED_LOGINS:
                lock_user_account(int(row_get(u, "id")))
                otp = set_user_otp(int(row_get(u, "id")), purpose="unlock")
                send_otp_email(row_get(u, "email"), otp, purpose="unlock")
                session["unlock_user_id"] = row_get(u, "id")
                flash("Too many failed attempts. Your account is locked. We emailed you an OTP to unlock it.")
                return redirect(url_for("unlock_account"))

            db.execute("UPDATE users SET failed_login_attempts=? WHERE id=?", (attempts, int(row_get(u, "id"))))
            db.commit()
            flash("Invalid email or password.")
            return redirect(url_for("login"))

        reset_failed_logins(int(row_get(u, "id")))
        session["user_id"] = row_get(u, "id")
        _captcha_clear()

        if not user_is_verified(u):
            otp = set_user_otp(int(row_get(u, "id")), purpose="verify")
            send_otp_email(row_get(u, "email"), otp, purpose="verify")
            session["verify_user_id"] = row_get(u, "id")
            flash("Please verify your email. We sent you a 6-digit OTP.")
            return redirect(url_for("verify_email"))

        flash("Logged in.")
        nxt = request.args.get("next") or url_for("home")
        return redirect(nxt)

    # ---------- LOGOUT ----------
    @app.route("/logout")
    def logout():
        session.pop("user_id", None)
        flash("Logged out.")
        return redirect(url_for("home"))

    # ---------- CHANGE PASSWORD ----------
    @app.route("/change-password", methods=["GET", "POST"], endpoint="change_password")
    @login_required
    def change_password():
        u = current_user()
        if not u:
            return redirect(url_for("login"))

        if request.method == "POST":
            old_pw = (request.form.get("old_password") or "").strip()
            new_pw = request.form.get("new_password") or ""
            confirm_pw = request.form.get("confirm_password") or ""

            if not check_password_hash(row_get(u, "password_hash", "") or "", old_pw):
                flash("Old password is incorrect.")
                return redirect(url_for("change_password"))

            if new_pw != confirm_pw:
                flash("New passwords do not match.")
                return redirect(url_for("change_password"))

            ok, msg = validate_password(new_pw)
            if not ok:
                flash(msg)
                return redirect(url_for("change_password"))

            db = get_db()
            db.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (generate_password_hash(new_pw), int(row_get(u, "id"))),
            )
            db.commit()

            flash("Password changed successfully ✅")
            return redirect(url_for("home"))

        return render_template("auth_change_password.html", user=u)

    # ---------- VERIFY EMAIL ----------
    @app.route("/verify-email", methods=["GET", "POST"])
    def verify_email():
        u = current_user()
        user_id = None
        email = None

        if u:
            user_id = row_get(u, "id")
            email = row_get(u, "email")
            if user_is_verified(u):
                flash("Your email is already verified.")
                return redirect(url_for("home"))
        else:
            user_id = session.get("verify_user_id")
            if user_id:
                row = get_db().execute("SELECT email, is_verified FROM users WHERE id=?", (int(user_id),)).fetchone()
                if not row:
                    flash("Please register or log in.")
                    return redirect(url_for("login"))
                email = row_get(row, "email")
                if int(row_get(row, "is_verified", 0) or 0) == 1:
                    flash("Your email is already verified.")
                    return redirect(url_for("login"))
            else:
                flash("Please register or log in.")
                return redirect(url_for("login"))

        if request.method == "POST":
            otp = (request.form.get("otp") or "").strip()
            action = request.form.get("action") or "verify"

            if action == "resend":
                new_otp = set_user_otp(int(user_id), purpose="verify")
                sent = send_otp_email(email, new_otp, purpose="verify")
                flash("OTP resent ✅" if sent else "Could not send OTP email. Please check SMTP settings.")
                return redirect(url_for("verify_email"))

            if not otp:
                flash("Please enter the OTP from your email.")
                return redirect(url_for("verify_email"))

            ok = verify_user_otp(int(user_id), otp, purpose="verify")
            if not ok:
                flash("Invalid or expired OTP. Please try again or resend a new code.")
                return redirect(url_for("verify_email"))

            db = get_db()
            db.execute("UPDATE users SET is_verified=1 WHERE id=?", (int(user_id),))
            db.commit()

            session.pop("verify_user_id", None)
            flash("Email verified ✅ You can log in now.")
            return redirect(url_for("login"))

        return render_template("auth_verify_email.html", user=current_user(), email=email)

    # ---------- UNLOCK ACCOUNT ----------
    @app.route("/unlock", methods=["GET", "POST"])
    def unlock_account():
        user_id = session.get("unlock_user_id")
        if not user_id:
            flash("Please log in.")
            return redirect(url_for("login"))

        db = get_db()
        u = db.execute("SELECT id, email FROM users WHERE id=?", (int(user_id),)).fetchone()
        if not u:
            session.pop("unlock_user_id", None)
            flash("Please log in.")
            return redirect(url_for("login"))

        email = row_get(u, "email")

        if request.method == "POST":
            otp = (request.form.get("otp") or "").strip()
            if not otp:
                flash("Please enter the OTP from your email.")
                return redirect(url_for("unlock_account"))

            ok = verify_user_otp(int(user_id), otp, purpose="unlock")
            if not ok:
                flash("Invalid or expired OTP. Please try again or resend a new code.")
                return redirect(url_for("unlock_account"))

            db.execute(
                "UPDATE users SET is_locked=0, failed_login_attempts=0 WHERE id=?",
                (int(user_id),),
            )
            db.commit()

            session.pop("unlock_user_id", None)
            flash("Account unlocked ✅ You can now log in.")
            return redirect(url_for("login"))

        return render_template("auth_unlock.html", email=email)

    # ---------- RESEND OTP ----------
    @app.route("/resend-otp", methods=["POST"], endpoint="resend_otp")
    def resend_otp():
        unlock_user_id = session.get("unlock_user_id")
        if unlock_user_id:
            row = get_db().execute("SELECT email FROM users WHERE id=?", (int(unlock_user_id),)).fetchone()
            if not row:
                session.pop("unlock_user_id", None)
                return redirect(url_for("login"))

            email = row_get(row, "email")
            new_otp = set_user_otp(int(unlock_user_id), purpose="unlock")
            sent = send_otp_email(email, new_otp, purpose="unlock")
            flash("OTP resent ✅" if sent else "Could not send OTP email. Please check SMTP settings.")
            return redirect(url_for("unlock_account"))

        u = current_user()
        user_id = int(row_get(u, "id")) if u else session.get("verify_user_id")
        if not user_id:
            return redirect(url_for("login"))

        row = get_db().execute("SELECT email, is_verified FROM users WHERE id=?", (int(user_id),)).fetchone()
        if not row:
            return redirect(url_for("login"))

        if int(row_get(row, "is_verified", 0) or 0) == 1:
            flash("Email is already verified.")
            return redirect(url_for("home"))

        otp = set_user_otp(int(user_id), purpose="verify")
        sent = send_otp_email(row_get(row, "email"), otp, purpose="verify")
        flash("OTP resent ✅" if sent else "Could not send OTP email. Check SMTP settings.")
        return redirect(url_for("verify_email"))

    # ---------- FORGOT PASSWORD ----------
    @app.route("/forgot-password", methods=["GET", "POST"], endpoint="forgot_password")
    def forgot_password():
        email = (request.form.get("email") if request.method == "POST" else request.args.get("email"))
        email = (email or "").strip().lower()

        if request.method == "POST":
            if not email:
                flash("Please enter your email.")
                return render_template("auth_forgot_password.html", user=current_user(), email=email)

            db = get_db()
            row = db.execute("SELECT id, email FROM users WHERE lower(email)=?", (email,)).fetchone()
            if not row:
                flash("User not found.")
                return render_template("auth_forgot_password.html", user=current_user(), email=email)

            otp = _issue_forgot_pw_otp(int(row_get(row, "id")))
            sent = send_otp_email(row_get(row, "email"), otp, purpose="reset")
            if not sent:
                flash("Could not send OTP email. Check SMTP settings.")
                return render_template("auth_forgot_password.html", user=current_user(), email=email)

            session["forgot_pw_user_id"] = int(row_get(row, "id"))
            flash("OTP sent ✅ Check your email.")
            return redirect(url_for("forgot_password_reset", email=row_get(row, "email")))

        return render_template("auth_forgot_password.html", user=current_user(), email=email)

    @app.route("/forgot-password/reset", methods=["GET", "POST"], endpoint="forgot_password_reset")
    def forgot_password_reset():
        email = (request.form.get("email") if request.method == "POST" else request.args.get("email"))
        email = (email or "").strip().lower()

        user_id = session.get("forgot_pw_user_id")
        if not user_id and email:
            row = get_db().execute("SELECT id FROM users WHERE lower(email)=?", (email,)).fetchone()
            if row:
                user_id = int(row_get(row, "id"))
                session["forgot_pw_user_id"] = user_id

        if not user_id:
            flash("Please request an OTP first.")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            otp = (request.form.get("otp") or "").strip()
            pw1 = request.form.get("password1") or ""
            pw2 = request.form.get("password2") or ""

            if not email:
                row_email = get_db().execute("SELECT email FROM users WHERE id=?", (int(user_id),)).fetchone()
                email = (row_get(row_email, "email") if row_email else "")

            if not otp:
                flash("Enter the OTP.")
                return render_template("auth_forgot_password_reset.html", user=current_user(), email=email)

            if pw1 != pw2:
                flash("Passwords do not match.")
                return render_template("auth_forgot_password_reset.html", user=current_user(), email=email)

            ok, msg = validate_password(pw1)
            if not ok:
                flash(msg)
                return render_template("auth_forgot_password_reset.html", user=current_user(), email=email)

            row = _get_forgot_pw_row(int(user_id))
            if not row:
                flash("OTP not found. Please request a new one.")
                return redirect(url_for("forgot_password", email=email))

            expires_at = row_get(row, "expires_at")
            try:
                exp_dt = datetime.fromisoformat(expires_at)
            except Exception:
                exp_dt = datetime.now(timezone.utc) - timedelta(seconds=1)

            if exp_dt < datetime.now(timezone.utc):
                _clear_forgot_pw_otps(int(user_id))
                flash("OTP expired. Please request a new one.")
                return redirect(url_for("forgot_password", email=email))

            if not check_password_hash(row_get(row, "otp_hash"), otp):
                flash("Invalid OTP.")
                return render_template("auth_forgot_password_reset.html", user=current_user(), email=email)

            # Reset ALSO unlocks + clears attempts
            db = get_db()
            db.execute(
                """
                UPDATE users
                SET password_hash=?,
                    is_locked=0,
                    failed_login_attempts=0
                WHERE id=?
                """,
                (generate_password_hash(pw1), int(user_id)),
            )
            db.commit()

            _clear_forgot_pw_otps(int(user_id))
            session.pop("forgot_pw_user_id", None)
            session.pop("unlock_user_id", None)

            flash("Password updated ✅ You can now log in.")
            return redirect(url_for("login"))

        return render_template("auth_forgot_password_reset.html", user=current_user(), email=email)

    @app.route("/forgot-password/resend", methods=["POST"], endpoint="forgot_password_resend")
    def forgot_password_resend():
        email = (request.form.get("email") or "").strip().lower()
        if not email:
            flash("Please enter your email.")
            return redirect(url_for("forgot_password"))

        row = get_db().execute("SELECT id, email FROM users WHERE lower(email)=?", (email,)).fetchone()
        if not row:
            flash("User not found.")
            return redirect(url_for("forgot_password"))

        otp = _issue_forgot_pw_otp(int(row_get(row, "id")))
        sent = send_otp_email(row_get(row, "email"), otp, purpose="reset")
        flash("OTP resent ✅" if sent else "Could not send OTP email. Check SMTP settings.")
        session["forgot_pw_user_id"] = int(row_get(row, "id"))
        return redirect(url_for("forgot_password_reset", email=row_get(row, "email")))
