# photos_routes.py (FULL - Google Drive uploads + safe fallback)
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

# ✅ Google Drive uploader
try:
    from gdrive_storage import drive_enabled, upload_file_to_drive
except Exception:
    drive_enabled = None
    upload_file_to_drive = None


def _is_url(s: str) -> bool:
    s = (s or "").strip().lower()
    return s.startswith("http://") or s.startswith("https://")


def _looks_like_drive_file_id(s: str) -> bool:
    """
    Heuristic: Drive file IDs are typically long-ish, no slashes, no spaces.
    """
    s = (s or "").strip()
    if not s:
        return False
    if "/" in s or " " in s:
        return False
    # file ids are usually >= 20 chars, but be lenient
    return len(s) >= 15


def _drive_img_url(file_id: str) -> str:
    """
    Best for <img src="..."> publicly
    """
    fid = (file_id or "").strip()
    return f"https://drive.google.com/uc?export=view&id={fid}"


def _drive_download_url(file_id: str) -> str:
    fid = (file_id or "").strip()
    return f"https://drive.google.com/uc?id={fid}&export=download"


def _public_media_url(stored_value: str) -> str:
    """
    Converts DB value into a usable URL.

    Supported stored formats:
    - Full URL (https://...) -> returned as-is
    - Google Drive file_id -> converted into uc?export=view URL
    - Legacy local filename -> /static/uploads/<name>
    """
    v = (stored_value or "").strip()
    if not v:
        return ""

    if _is_url(v):
        return v

    if _looks_like_drive_file_id(v):
        return _drive_img_url(v)

    # legacy local uploads
    return url_for("static", filename=f"uploads/{v}")


def _save_to_storage(file, filename: str) -> str:
    """
    Saves to Google Drive if configured, otherwise saves to local UPLOAD_FOLDER.

    Returns:
      - Drive file_id (preferred + persistent across deploys)
      - or local filename (fallback)
    """
    drive_ok = (
        upload_file_to_drive is not None
        and callable(upload_file_to_drive)
        and drive_enabled is not None
        and callable(drive_enabled)
        and drive_enabled()
    )

    if drive_ok:
        # ✅ Upload to Drive and store the returned Drive file_id
        return upload_file_to_drive(file, filename)

    # Fallback: local save (will be wiped on Render deploy, but app won't break)
    save_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
    file.save(save_path)
    return filename


def _row_to_dict(r):
    """
    Converts sqlite3.Row or dict into a plain dict for templates.
    """
    if r is None:
        return {}
    if isinstance(r, dict):
        return dict(r)
    try:
        return {k: r[k] for k in r.keys()}
    except Exception:
        # last resort
        try:
            return dict(r)
        except Exception:
            return {"file_name": None}


def get_photos(event_id: int, kind: str):
    rows = get_db().execute(
        "SELECT * FROM event_photos WHERE event_id=? AND kind=? ORDER BY created_at DESC",
        (event_id, kind)
    ).fetchall()

    out = []
    for r in rows or []:
        rr = _row_to_dict(r)
        rr["file_url"] = _public_media_url(rr.get("file_name"))
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

            for file in files:
                if not file or file.filename == "":
                    continue
                if not allowed_file(file.filename):
                    continue

                filename = secure_filename(file.filename)
                unique_name = f"{slug}-photos-{secrets.token_hex(6)}-{filename}"

                # ✅ Save to Drive (file_id) or local fallback
                stored_value = _save_to_storage(file, unique_name)

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
                    )
                )
                saved += 1

            db.commit()
            flash(f"Uploaded {saved} photo(s).")
            return redirect(url_for("event_photos", slug=slug))

        photos = get_photos(event["id"], "photos")

        # music row
        music_row = get_db().execute(
            "SELECT * FROM event_photos WHERE event_id=? AND kind=? ORDER BY created_at DESC LIMIT 1",
            (event["id"], "photos_music")
        ).fetchone()

        music_file = None
        music_url = None
        music_download_url = None
        if music_row:
            mr = _row_to_dict(music_row)
            music_file = mr.get("file_name")
            # For audio, prefer download URL for best compatibility
            if _looks_like_drive_file_id(music_file):
                music_url = _drive_download_url(music_file)
                music_download_url = music_url
            else:
                music_url = _public_media_url(music_file)
                music_download_url = music_url

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
            music_download_url=music_download_url,
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

        # ✅ Save to Drive (file_id) or local fallback
        stored_value = _save_to_storage(f, filename)

        db = get_db()
        db.execute("DELETE FROM event_photos WHERE event_id=? AND kind=?", (event["id"], "photos_music"))
        db.execute(
            """
            INSERT INTO event_photos(event_id, kind, file_name, uploader_user_id, uploader_name, created_at)
            VALUES (?,?,?,?,?,?)
            """,
            (event["id"], "photos_music", stored_value, current_user()["id"], "", now_iso())
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

        token = settings["token"] or ensure_photos_day_token(event["id"])

        if request.method == "POST":
            action = (request.form.get("action") or "").strip()
            if action == "open":
                db.execute(
                    "UPDATE photos_day_settings SET is_open=1, token=?, updated_at=? WHERE event_id=?",
                    (token, now_iso(), event["id"])
                )
                db.commit()
                flash("Photos of the Day is now OPEN. Share the link below.")
                return redirect(url_for("photos_day_admin", slug=slug))

            if action == "close":
                db.execute(
                    "UPDATE photos_day_settings SET is_open=0, updated_at=? WHERE event_id=?",
                    (now_iso(), event["id"])
                )
                db.commit()
                flash("Photos of the Day is now CLOSED.")
                return redirect(url_for("photos_day_admin", slug=slug))

            if action == "regen":
                new_token = secrets.token_urlsafe(16)
                db.execute(
                    "UPDATE photos_day_settings SET token=?, updated_at=? WHERE event_id=?",
                    (new_token, now_iso(), event["id"])
                )
                db.commit()
                flash("New link generated.")
                return redirect(url_for("photos_day_admin", slug=slug))

        settings = db.execute("SELECT * FROM photos_day_settings WHERE event_id=?", (event["id"],)).fetchone()
        photos = get_photos(event["id"], "photos_day")

        share_url = url_for("photos_day_upload", token=settings["token"], _external=True)

        return render_template(
            "event_photos_day_admin.html",
            user=current_user(),
            event=event,
            sections=sections,
            section_key=section_key,
            section=section,
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

        event = db.execute("SELECT * FROM events WHERE id=?", (settings["event_id"],)).fetchone()
        if not event:
            return render_template("not_found.html", user=current_user()), 404

        if int(settings["is_open"]) != 1:
            flash("This upload link is currently closed.")
            return redirect(url_for("events"))

        u = current_user()
        rsvp = db.execute(
            "SELECT first_name, last_name FROM rsvp_responses WHERE event_id=? AND user_id=? ORDER BY id DESC LIMIT 1",
            (event["id"], u["id"])
        ).fetchone()

        default_name = ""
        if rsvp:
            default_name = f"{rsvp['first_name']} {rsvp['last_name']}".strip()

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
            for file in files:
                if not file or file.filename == "":
                    continue
                if not allowed_file(file.filename):
                    continue

                filename = secure_filename(file.filename)
                unique_name = f"{event['slug']}-photosday-{secrets.token_hex(6)}-{filename}"

                stored_value = _save_to_storage(file, unique_name)

                db.execute(
                    """
                    INSERT INTO event_photos(event_id, kind, file_name, uploader_user_id, uploader_name, created_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (event["id"], "photos_day", stored_value, u["id"], uploader_name, now_iso())
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
