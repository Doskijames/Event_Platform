# photos_routes.py
# Full replacement with:
# - Google Drive OAuth support (stores Drive URL in DB instead of local filename)
# - Works with upload_file_to_drive returning either:
#     dict {"file_id","view_url","download_url"}  OR  string (URL or file_id)
# - Local fallback still supported (legacy)

import os
import time
import secrets
from datetime import datetime, timezone

from flask import (
    render_template, request, redirect, url_for,
    flash, abort, current_app
)
from werkzeug.utils import secure_filename

from db_core import get_db, ensure_default_sections
from utils_core import has_event_access, ensure_photos_day_token, now_iso
from auth_routes import current_user, login_required
from events_routes import get_event_by_slug, get_event_sections, can_manage_event, allowed_file

# Google Drive uploader (OAuth)
try:
    from gdrive_storage import (
        drive_enabled,
        upload_file_to_drive,
        get_drive_service,
        drive_file_embed_url,
    )
except Exception:
    drive_enabled = None
    upload_file_to_drive = None
    get_drive_service = None
    drive_file_embed_url = None


def _drive_uc_url(file_id: str, *, mode: str = "view") -> str:
    mode = (mode or "view").strip().lower()
    if mode not in ("view", "download"):
        mode = "view"
    return f"https://drive.google.com/uc?export={mode}&id={file_id}"


def _drive_ok() -> bool:
    if upload_file_to_drive is None:
        return False

    if callable(drive_enabled):
        try:
            return bool(drive_enabled())
        except Exception:
            pass

    has_folder = bool((os.getenv("GOOGLE_DRIVE_FOLDER_ID") or "").strip())
    has_client_json = bool((os.getenv("GOOGLE_OAUTH_CLIENT_SECRET_JSON") or "").strip()
                           or (os.getenv("GOOGLE_OAUTH_CLIENT_SECRET_JSON_BASE64") or "").strip())
    has_refresh = bool((os.getenv("GOOGLE_OAUTH_REFRESH_TOKEN") or "").strip())
    return has_folder and has_client_json and has_refresh


def _is_url(s: str) -> bool:
    s = (s or "").strip().lower()
    return s.startswith("http://") or s.startswith("https://")


def _looks_like_drive_file_id(s: str) -> bool:
    """Heuristic: DB may contain a raw Drive file_id (legacy)."""
    v = (s or "").strip()
    if not v:
        return False
    if _is_url(v):
        return False
    if "/" in v or "\\" in v:
        return False
    if "." in v:  # local filename usually has extension
        return False
    if len(v) < 18 or len(v) > 200:
        return False
    for ch in v:
        if not (ch.isalnum() or ch in "-_"):
            return False
    return True


def _local_upload_exists(filename: str) -> bool:
    """Return True if a legacy local upload still exists on disk."""
    fn = (filename or "").strip()
    if not fn or _is_url(fn) or _looks_like_drive_file_id(fn):
        return False
    try:
        base = current_app.config.get("UPLOAD_FOLDER") or ""
        if not base:
            return False
        return os.path.exists(os.path.join(base, fn))
    except Exception:
        return False


# Simple in-memory cache to avoid calling Drive list() repeatedly.
_DRIVE_NAME_URL_CACHE = {}


def _drive_url_for_filename(filename: str) -> str:
    """Try to resolve a legacy stored filename to a Drive URL by searching within
    the configured folder (GOOGLE_DRIVE_FOLDER_ID). Returns "" if not found."""
    fn = (filename or "").strip()
    if not fn or _is_url(fn) or _looks_like_drive_file_id(fn):
        return ""

    if fn in _DRIVE_NAME_URL_CACHE:
        return _DRIVE_NAME_URL_CACHE.get(fn, "")

    if not callable(drive_enabled) or not drive_enabled():
        _DRIVE_NAME_URL_CACHE[fn] = ""
        return ""

    if not callable(get_drive_service) or not callable(drive_file_embed_url):
        _DRIVE_NAME_URL_CACHE[fn] = ""
        return ""

    folder_id = (os.getenv("GOOGLE_DRIVE_FOLDER_ID") or "").strip()
    if not folder_id:
        _DRIVE_NAME_URL_CACHE[fn] = ""
        return ""

    # Escape single quotes for Drive query.
    safe_name = fn.replace("'", "\\'")
    q = f"name='{safe_name}' and '{folder_id}' in parents and trashed=false"

    try:
        svc = get_drive_service()
        res = svc.files().list(
            q=q,
            fields="files(id, name, createdTime)",
            pageSize=1,
            orderBy="createdTime desc",
        ).execute()
        files = res.get("files") or []
        if files:
            url = drive_file_embed_url(files[0]["id"])
            _DRIVE_NAME_URL_CACHE[fn] = url
            return url
    except Exception:
        pass

    _DRIVE_NAME_URL_CACHE[fn] = ""
    return ""


def _public_media_url(stored_value: str):
    """
    Converts what's stored in DB into a usable URL.

    - If it's already a URL (Google Drive), return it.
    - If it's a raw Drive file_id (legacy), convert it to a Drive URL.
    - If it's a local filename AND it exists, return a local URL.
    - If local filename is missing (common on Render), return empty string to avoid 404 spam.
    """
    v = (stored_value or "").strip()
    if not v:
        return ""
    if _is_url(v):
        return v
    if _looks_like_drive_file_id(v):
        return _drive_uc_url(v)
    if _local_upload_exists(v):
        return url_for("static", filename=f"uploads/{v}")

    # Last resort: the DB might contain only the original filename even though the
    # file actually lives in Drive. Try to find it in the configured Drive folder.
    return _drive_url_for_filename(v)
def _save_to_storage(file_storage, filename: str) -> str:
    """
    Saves to Google Drive if configured, otherwise saves to local UPLOAD_FOLDER.

    Returns:
      - Google Drive public URL (string)
      - or local filename (fallback)
    """
    current_app.logger.warning(
        "UPLOAD: drive_ok=%s upload_func=%s has_folder=%s has_client_json=%s has_refresh=%s",
        _drive_ok(),
        bool(upload_file_to_drive),
        bool((os.getenv("GOOGLE_DRIVE_FOLDER_ID") or "").strip()),
        bool((os.getenv("GOOGLE_OAUTH_CLIENT_SECRET_JSON") or "").strip()
             or (os.getenv("GOOGLE_OAUTH_CLIENT_SECRET_JSON_BASE64") or "").strip()),
        bool((os.getenv("GOOGLE_OAUTH_REFRESH_TOKEN") or "").strip()),
    )

    if _drive_ok():
        try:
            meta = upload_file_to_drive(file_storage, filename=filename, make_public=True)
            mime_type = getattr(file_storage, "mimetype", "") or ""
            mode = "view" if mime_type.startswith("image/") else "download"

            # Dict response
            if isinstance(meta, dict):
                url = (meta.get("download_url") or "").strip() or (meta.get("view_url") or "").strip()
                if url and url.startswith("http"):
                    return url

                file_id = (meta.get("file_id") or "").strip()
                if file_id:
                    return _drive_uc_url(file_id, mode=mode)

            # String response (URL or file_id)
            if isinstance(meta, str):
                s = meta.strip()
                if s.startswith("http"):
                    return s
                if s:
                    return _drive_uc_url(s, mode=mode)

        except Exception as e:
            current_app.logger.exception("Drive upload failed; falling back to local save. err=%s", e)

    # Local fallback (legacy)
    save_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
    file_storage.save(save_path)
    return filename


def get_photos(event_id: int, kind: str):
    rows = get_db().execute(
        "SELECT * FROM event_photos WHERE event_id=? AND kind=? ORDER BY created_at DESC",
        (event_id, kind),
    ).fetchall() or []

    out = []
    for r in rows:
        if isinstance(r, dict):
            rr = dict(r)
        else:
            rr = {k: r[k] for k in r.keys()}  # sqlite3.Row -> dict
        rr["file_url"] = _public_media_url(rr.get("file_name", ""))
        out.append(rr)

    return out


def register_photo_routes(app):

    @app.route("/events/<slug>/photos", methods=["GET", "POST"])
    @login_required
    def event_photos(slug):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_access(slug):
            return redirect(url_for("event_gate", slug=slug))

        ensure_default_sections(event["id"])
        sections = get_event_sections(event["id"])
        section_key = "photos"
        section = sections.get("photos")
        is_admin = can_manage_event(event)

        if request.method == "POST":
            if not is_admin:
                abort(403)

            files = request.files.getlist("photos")
            if not files:
                flash("Please select photos to upload.")
                return redirect(url_for("event_photos", slug=slug))

            saved = 0
            db = get_db()

            for f in files:
                if not f or not f.filename:
                    continue
                if not allowed_file(f.filename):
                    continue

                filename = secure_filename(f.filename)
                unique_name = f"{slug}-photos-{secrets.token_hex(6)}-{filename}"

                stored_value = _save_to_storage(f, unique_name)

                db.execute(
                    """
                    INSERT INTO event_photos(event_id, kind, file_name, uploader_user_id, uploader_name, created_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (
                        event["id"],
                        "photos",
                        stored_value,
                        current_user()["id"],
                        "",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                saved += 1

            db.commit()
            flash(f"Uploaded {saved} photo(s).")
            return redirect(url_for("event_photos", slug=slug))

        photos = get_photos(event["id"], "photos")

        # music row
        music_row = get_db().execute(
            "SELECT * FROM event_photos WHERE event_id=? AND kind=? ORDER BY created_at DESC LIMIT 1",
            (event["id"], "photos_music"),
        ).fetchone()

        music_file = None
        music_url = None
        if music_row:
            if isinstance(music_row, dict):
                music_file = music_row.get("file_name")
            else:
                music_file = music_row["file_name"]
            music_url = _public_media_url(music_file)

        return render_template(
            "event_photos.html",
            user=current_user(),
            event=event,
            sections=sections,
            section_key=section_key,
            section=section,
            is_admin=is_admin,
            photos=photos,
            music_file=music_file,
            music_url=music_url,
        )

    @app.post("/events/<slug>/photos/music")
    @login_required
    def photos_music_upload(slug):
        event = get_event_by_slug(slug)
        if not event:
            abort(404)
        if not can_manage_event(event):
            flash("You don't have permission to upload music for this event.")
            return redirect(url_for("event_photos", slug=slug))

        f = request.files.get("music")
        if not f or not f.filename:
            flash("Please choose an audio file.")
            return redirect(url_for("event_photos", slug=slug))

        allowed = {".mp3", ".wav", ".m4a", ".aac", ".ogg"}
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in allowed:
            flash("Unsupported audio type. Please upload MP3, WAV, M4A, AAC, or OGG.")
            return redirect(url_for("event_photos", slug=slug))

        filename = secure_filename(f"music_{slug}_{int(time.time())}{ext}")

        stored_value = _save_to_storage(f, filename)

        db = get_db()
        db.execute("DELETE FROM event_photos WHERE event_id=? AND kind=?", (event["id"], "photos_music"))
        db.execute(
            """
            INSERT INTO event_photos(event_id, kind, file_name, uploader_user_id, uploader_name, created_at)
            VALUES (?,?,?,?,?,?)
            """,
            (event["id"], "photos_music", stored_value, current_user()["id"], "", now_iso()),
        )
        db.commit()

        flash("Music uploaded ✅")
        return redirect(url_for("event_photos", slug=slug))

    # -------------------- PHOTOS OF THE DAY --------------------
    @app.route("/events/<slug>/photos-day", methods=["GET", "POST"])
    @login_required
    def photos_day_admin(slug):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_access(slug):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            return ("Forbidden", 403)

        ensure_default_sections(event["id"])
        sections = get_event_sections(event["id"])
        section_key = "photos-day"
        section = sections.get("photos-day")

        db = get_db()
        settings = db.execute("SELECT * FROM photos_day_settings WHERE event_id=?", (event["id"],)).fetchone()
        if not settings:
            ensure_photos_day_token(event["id"])
            settings = db.execute("SELECT * FROM photos_day_settings WHERE event_id=?", (event["id"],)).fetchone()

        token = (settings["token"] if isinstance(settings, dict) else settings["token"]) or ensure_photos_day_token(event["id"])

        if request.method == "POST":
            action = (request.form.get("action") or "").strip()
            if action == "open":
                db.execute(
                    "UPDATE photos_day_settings SET is_open=1, token=?, updated_at=? WHERE event_id=?",
                    (token, now_iso(), event["id"]),
                )
                db.commit()
                flash("Photos of the Day is now OPEN. Share the link below.")
                return redirect(url_for("photos_day_admin", slug=slug))

            if action == "close":
                db.execute(
                    "UPDATE photos_day_settings SET is_open=0, updated_at=? WHERE event_id=?",
                    (now_iso(), event["id"]),
                )
                db.commit()
                flash("Photos of the Day is now CLOSED.")
                return redirect(url_for("photos_day_admin", slug=slug))

            if action == "regen":
                new_token = secrets.token_urlsafe(16)
                db.execute(
                    "UPDATE photos_day_settings SET token=?, updated_at=? WHERE event_id=?",
                    (new_token, now_iso(), event["id"]),
                )
                db.commit()
                flash("New link generated.")
                return redirect(url_for("photos_day_admin", slug=slug))

        settings = db.execute("SELECT * FROM photos_day_settings WHERE event_id=?", (event["id"],)).fetchone()
        photos = get_photos(event["id"], "photos_day")

        share_url = url_for(
            "photos_day_upload",
            token=(settings["token"] if isinstance(settings, dict) else settings["token"]),
            _external=True,
        )

        return render_template(
            "event_photos_day_admin.html",
            user=current_user(),
            event=event,
            sections=sections,
            section_key=section_key,
            is_admin=True,
            settings=settings,
            share_url=share_url,
            photos=photos,
        )

    @app.route("/p/<token>", methods=["GET", "POST"])
    @login_required
    def photos_day_upload(token):
        db = get_db()
        settings = db.execute("SELECT * FROM photos_day_settings WHERE token=?", (token,)).fetchone()
        if not settings:
            return render_template("not_found.html", user=current_user()), 404

        event_id = settings["event_id"] if isinstance(settings, dict) else settings["event_id"]
        is_open = settings["is_open"] if isinstance(settings, dict) else settings["is_open"]

        event = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        if not event:
            return render_template("not_found.html", user=current_user()), 404

        if int(is_open) != 1:
            flash("This upload link is currently closed.")
            return redirect(url_for("events"))

        u = current_user()
        rsvp = db.execute(
            "SELECT first_name, last_name FROM rsvp_responses WHERE event_id=? AND user_id=? ORDER BY id DESC LIMIT 1",
            (event_id, u["id"]),
        ).fetchone()

        default_name = ""
        if rsvp:
            first = rsvp["first_name"] if isinstance(rsvp, dict) else rsvp["first_name"]
            last = rsvp["last_name"] if isinstance(rsvp, dict) else rsvp["last_name"]
            default_name = f"{first} {last}".strip()

        if request.method == "POST":
            uploader_name = (request.form.get("uploader_name") or "").strip()
            if not uploader_name:
                flash("Please enter your name.")
                return redirect(url_for("photos_day_upload", token=token))

            files = request.files.getlist("photos")
            if not files:
                flash("Please select photo(s) to upload.")
                return redirect(url_for("photos_day_upload", token=token))

            saved = 0
            slug_val = event["slug"] if isinstance(event, dict) else event["slug"]

            for f in files:
                if not f or not f.filename:
                    continue
                if not allowed_file(f.filename):
                    continue

                filename = secure_filename(f.filename)
                unique_name = f"{slug_val}-photosday-{secrets.token_hex(6)}-{filename}"

                stored_value = _save_to_storage(f, unique_name)

                db.execute(
                    """
                    INSERT INTO event_photos(event_id, kind, file_name, uploader_user_id, uploader_name, created_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (event_id, "photos_day", stored_value, u["id"], uploader_name, now_iso()),
                )
                saved += 1

            db.commit()
            flash(f"Thanks! Uploaded {saved} photo(s).")
            return redirect(url_for("photos_day_upload", token=token))

        return render_template(
            "photos_day_upload.html",
            user=current_user(),
            event=event,
            token=token,
            default_name=default_name,
        )
