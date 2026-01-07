# photos_routes.py (FULL - compatible with the corrected db_core.py)
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


def get_photos(event_id: int, kind: str):
    return get_db().execute(
        "SELECT * FROM event_photos WHERE event_id=? AND kind=? ORDER BY created_at DESC",
        (event_id, kind)
    ).fetchall()


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
            for file in files:
                if not file or file.filename == "":
                    continue
                if not allowed_file(file.filename):
                    continue

                filename = secure_filename(file.filename)
                unique_name = f"{slug}-photos-{secrets.token_hex(6)}-{filename}"
                file.save(os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name))

                get_db().execute(
                    """
                    INSERT INTO event_photos(event_id, kind, file_name, uploader_user_id, uploader_name, created_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (event["id"], "photos", unique_name, current_user()["id"], "", datetime.now(timezone.utc).isoformat())
                )
                saved += 1

            get_db().commit()
            flash(f"Uploaded {saved} photo(s).")
            return redirect(url_for("event_photos", slug=slug))

        photos = get_photos(event["id"], "photos")

        music_rows = get_photos(event["id"], "photos_music")
        music_file = music_rows[0]["file_name"] if music_rows else None

        return render_template(
            "event_photos.html",
            user=current_user(),
            event=event,
            sections=sections,
            section_key=section_key,
            section=section,
            is_admin=is_admin,
            photos=photos,
            music_file=music_file
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
        save_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        f.save(save_path)

        db = get_db()
        db.execute("DELETE FROM event_photos WHERE event_id=? AND kind=?", (event["id"], "photos_music"))
        db.execute(
            """
            INSERT INTO event_photos(event_id, kind, file_name, uploader_user_id, uploader_name, created_at)
            VALUES (?,?,?,?,?,?)
            """,
            (event["id"], "photos_music", filename, current_user()["id"], "", now_iso())
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
                file.save(os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name))

                db.execute(
                    """
                    INSERT INTO event_photos(event_id, kind, file_name, uploader_user_id, uploader_name, created_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (event["id"], "photos_day", unique_name, u["id"], uploader_name, now_iso())
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
