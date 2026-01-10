# events_routes.py
# Full replacement with:
# - Google Drive OAuth support (stores Drive URL in DB instead of local filename)
# - media_url helper used by templates
# - add_section sort_order fix
# - delete event route (with cascaded cleanup)
#
# Expected env vars (OAuth):
#   GOOGLE_DRIVE_FOLDER_ID
#   GOOGLE_OAUTH_CLIENT_SECRET_JSON (or GOOGLE_OAUTH_CLIENT_SECRET_JSON_BASE64)
#   GOOGLE_OAUTH_REFRESH_TOKEN

import os
import secrets
import re
import io
from datetime import datetime, timezone, datetime as dt_cls

from flask import (
    render_template, request, redirect, url_for,
    session, flash, abort, current_app, make_response, Response
)
from werkzeug.utils import secure_filename

# Google Drive uploader (OAuth)
try:
    from gdrive_storage import drive_enabled, upload_file_to_drive, get_drive_service
except Exception:
    drive_enabled = None
    upload_file_to_drive = None
    get_drive_service = None

from db_core import get_db, ensure_default_sections
from utils_core import (
    slugify, unique_slug, sanitize_quill_html,
    parse_qa_list_json, event_session_key
)
from auth_routes import current_user, login_required

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}


# -----------------------------
# Helpers
# -----------------------------
def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_event_by_slug(slug: str):
    return get_db().execute("SELECT * FROM events WHERE slug=?", (slug,)).fetchone()


def get_event_sections(event_id: int):
    rows = get_db().execute(
        "SELECT * FROM sections WHERE event_id=? ORDER BY sort_order ASC, id ASC",
        (event_id,),
    ).fetchall()
    return {r["section_key"]: r for r in rows}


def can_manage_event(event_row) -> bool:
    u = current_user()
    if not u:
        return False
    if (u.get("role") or u["role"] or "").lower() == "admin":
        return True
    if event_row.get("owner_user_id") and int(event_row["owner_user_id"]) == int(u["id"]):
        return True
    return False


def has_event_view_access(event_row) -> bool:
    """
    Enforce passcode access for event viewing.

    Rules:
    - Owner/admin can always view.
    - If passcode is empty/whitespace => event is public.
    - If passcode is set => viewer must have unlocked it in this browser session.
    """
    if not event_row:
        return False

    if can_manage_event(event_row):
        return True

    passcode = (event_row.get("passcode") or "").strip()
    if not passcode:
        return True

    return bool(session.get(event_session_key(event_row["id"])))


def preview_session_key(slug: str) -> str:
    return f"view_as_user:{slug}"


def parse_date_iso(date_iso: str):
    try:
        return dt_cls.strptime(date_iso, "%Y-%m-%d")
    except ValueError:
        return None


def format_weekday(d: dt_cls) -> str:
    return d.strftime("%A")


def format_long_date(d: dt_cls) -> str:
    return d.strftime("%B %d, %Y")


def countdown_target_iso(d: dt_cls) -> str:
    return d.strftime("%Y-%m-%dT00:00:00")


def unique_custom_section_key(event_id: int, title: str, prefix: str) -> str:
    base = slugify(title)[:40]
    key = f"{prefix}{base}"

    db = get_db()
    if not db.execute(
        "SELECT 1 FROM sections WHERE event_id=? AND section_key=? LIMIT 1",
        (event_id, key),
    ).fetchone():
        return key

    for i in range(2, 2000):
        cand = f"{key}-{i}"
        if not db.execute(
            "SELECT 1 FROM sections WHERE event_id=? AND section_key=? LIMIT 1",
            (event_id, cand),
        ).fetchone():
            return cand

    return f"{key}-{secrets.token_hex(3)}"


def _is_url(s: str) -> bool:
    s = (s or "").strip().lower()
    return s.startswith("http://") or s.startswith("https://")


def _drive_uc_view(file_id: str) -> str:
    return f"https://drive.google.com/uc?export=view&id={file_id}"


def _looks_like_drive_file_id(s: str) -> bool:
    """
    Heuristic: DB may contain a raw Drive file_id (legacy). If so, convert to Drive URL.
    Avoid treating normal filenames like *.jpg as IDs.
    """
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


def _extract_drive_file_id(value: str) -> str:
    """Extract Drive file_id from common URL formats, or return ''."""
    v = (value or "").strip()
    if not v:
        return ""

    # Querystring patterns: ...?id=<ID> or ...&id=<ID>
    m = re.search(r"(?:\?|&)id=([A-Za-z0-9_-]{10,})", v)
    if m:
        return m.group(1)

    # /file/d/<ID>/...
    m = re.search(r"/file/d/([A-Za-z0-9_-]{10,})", v)
    if m:
        return m.group(1)

    # open?id=<ID>
    m = re.search(r"open\?id=([A-Za-z0-9_-]{10,})", v)
    if m:
        return m.group(1)

    return ""


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


def resolve_media_url(value: str) -> str:
    """Return a browser-friendly URL for media stored as local filenames or Drive URLs/IDs."""
    v = (value or "").strip()
    if not v:
        return ""

    # If it's already a URL, normalize Drive links into our proxy where possible.
    if _is_url(v):
        file_id = _extract_drive_file_id(v)
        if file_id and _looks_like_drive_file_id(file_id):
            try:
                return url_for("drive_media", file_id=file_id)
            except Exception:
                # If url_for isn't available (very early init), fall back to direct view URL.
                return drive_file_embed_url(file_id)
        return v

    # If it's a bare Drive file id
    if _looks_like_drive_file_id(v):
        try:
            return url_for("drive_media", file_id=v)
        except Exception:
            return drive_file_embed_url(v)

    # Otherwise treat it as a local filename under static/uploads
    try:
        return url_for("static", filename=f"uploads/{v}")
    except Exception:
        return f"/static/uploads/{v}"

def _drive_ok() -> bool:
    """
    True if Drive uploader is available and OAuth env vars are present.
    """
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


def _next_sort_order(event_id: int) -> int:
    """
    Determine next sort_order for a newly added section.
    """
    db = get_db()
    row = db.execute(
        "SELECT COALESCE(MAX(sort_order), 0) AS m FROM sections WHERE event_id=?",
        (event_id,),
    ).fetchone()
    try:
        m = int(row["m"] if isinstance(row, dict) else row[0])
    except Exception:
        try:
            m = int(row["m"])
        except Exception:
            m = 0
    return m + 10


def _drive_upload_image_and_get_url(file_storage, unique_name: str) -> str:
    """
    Upload to Drive and return a URL suitable for <img src="...">.

    Works with both possible upload_file_to_drive return shapes:
      - dict: {"file_id","view_url","download_url"}
      - str:  URL OR "file_id"
    """
    if not _drive_ok():
        return ""

    current_app.logger.warning(
        "UPLOAD(image): drive_ok=%s upload_func=%s has_folder=%s has_client_json=%s has_refresh=%s",
        _drive_ok(),
        bool(upload_file_to_drive),
        bool((os.getenv("GOOGLE_DRIVE_FOLDER_ID") or "").strip()),
        bool((os.getenv("GOOGLE_OAUTH_CLIENT_SECRET_JSON") or "").strip()
             or (os.getenv("GOOGLE_OAUTH_CLIENT_SECRET_JSON_BASE64") or "").strip()),
        bool((os.getenv("GOOGLE_OAUTH_REFRESH_TOKEN") or "").strip()),
    )

    try:
        res = upload_file_to_drive(file_storage, filename=unique_name, make_public=True)

        # Dict response
        if isinstance(res, dict):
            url = (res.get("download_url") or "").strip() or (res.get("view_url") or "").strip()
            if url and url.startswith("http"):
                return url

            file_id = (res.get("file_id") or "").strip()
            if file_id:
                return _drive_uc_view(file_id)
            return ""

        # String response (URL or file_id)
        s = str(res or "").strip()
        if not s:
            return ""
        if s.startswith("http"):
            return s
        return _drive_uc_view(s)

    except Exception as e:
        current_app.logger.exception("Drive upload failed in events_routes. err=%s", e)
        return ""


# -----------------------------
# Routes
# -----------------------------
def register_event_routes(app):

    # Make media_url callable in ALL templates
    @app.context_processor
    def _inject_media_url():
        return {"resolve_media_url": resolve_media_url}

    @app.get("/media/drive/<file_id>")
    def drive_media(file_id: str):
        """Proxy Drive media through this app so <img> always works."""
        fid = (file_id or "").strip()
        if not fid or not _looks_like_drive_file_id(fid):
            abort(404)

        if not drive_enabled() or get_drive_service is None:
            # Fallback to direct link if Drive isn't configured
            return redirect(drive_file_embed_url(fid))

        try:
            service = get_drive_service()
            meta = service.files().get(fileId=fid, fields="mimeType,name").execute()
            mime = (meta or {}).get("mimeType") or "application/octet-stream"

            # Stream download to memory (images are small)
            from googleapiclient.http import MediaIoBaseDownload

            request = service.files().get_media(fileId=fid)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                _status, done = downloader.next_chunk()

            data = fh.getvalue()
            resp = make_response(data)
            resp.headers["Content-Type"] = mime
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return resp
        except Exception as e:
            current_app.logger.exception("Drive proxy failed for %s: %s", fid, e)
            abort(404)



        @app.route("/events")
        def events():
            rows = get_db().execute("SELECT * FROM events ORDER BY created_at DESC").fetchall()
            return render_template("events.html", user=current_user(), events=rows)

        @app.route("/events/create", methods=["GET", "POST"])
        @login_required
        def create_event():
            u = current_user()
            if request.method == "POST":
                name = (request.form.get("name") or "").strip()
                date_iso = (request.form.get("date_iso") or "").strip()
                location = (request.form.get("location") or "").strip()
                description = (request.form.get("description") or "").strip()
                passcode = (request.form.get("passcode") or "").strip()

                if not name or not date_iso or not location or not description:
                    flash("Please fill all required fields.")
                    return redirect(url_for("create_event"))

                if not passcode:
                    passcode = secrets.token_hex(3).upper()

                slug = unique_slug(slugify(name))

                db = get_db()
                now = datetime.now(timezone.utc).isoformat()
                db.execute(
                    """
                    INSERT INTO events(slug, name, date_iso, location, description, passcode, owner_user_id, cover_image, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (slug, name, date_iso, location, description, passcode, u["id"], "", now),
                )
                db.commit()

                new_event = get_event_by_slug(slug)
                ensure_default_sections(new_event["id"])

                flash(f"Event created! Passcode: {passcode}")
                return redirect(url_for("events"))

            return render_template("create_event.html", user=current_user())

    @app.route("/events/<slug>", methods=["GET", "POST"])
    def event_gate(slug):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404

        if not current_user():
            flash("Please log in first to access this event.")
            return redirect(url_for("login", next=url_for("event_gate", slug=slug)))

        if has_event_view_access(event):
            return redirect(url_for("event_section", slug=slug, section_key="home"))

        if request.method == "POST":
            passcode = (request.form.get("passcode") or "").strip()
            if passcode == (event.get("passcode") or event["passcode"]):
                session[event_session_key(event["id"])] = True
                return redirect(url_for("event_section", slug=slug, section_key="home"))
            flash("Incorrect passcode. Please try again.")

        return render_template("event_login.html", user=current_user(), event=event)

    @app.route("/events/<slug>/logout")
    def event_logout(slug):
        event = get_event_by_slug(slug)
        if event:
            session.pop(event_session_key(event["id"]), None)
        session.pop(f"event_{slug}", None)
        return redirect(url_for("events"))

    # ============================
    # DELETE EVENT (Admin any, Owner own)
    # ============================
    @app.post("/events/<slug>/delete", endpoint="delete_event")
    @login_required
    def delete_event(slug):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404

        if not can_manage_event(event):
            abort(403)

        db = get_db()
        event_id = int(event["id"])

        child_deletes = [
            ("DELETE FROM sections WHERE event_id=?", (event_id,)),
            ("DELETE FROM event_photos WHERE event_id=?", (event_id,)),
            ("DELETE FROM photos_day_settings WHERE event_id=?", (event_id,)),
            ("DELETE FROM rsvp_responses WHERE event_id=?", (event_id,)),
            ("DELETE FROM rsvps WHERE event_id=?", (event_id,)),  # legacy schema fallback
        ]
        for sql, params in child_deletes:
            try:
                db.execute(sql, params)
            except Exception:
                pass

        db.execute("DELETE FROM events WHERE id=?", (event_id,))
        db.commit()

        flash("Event deleted successfully 🗑️")
        return redirect(url_for("events"))

    # ============================
    # Upload section image (Drive URL stored in DB)
    # ============================
    @app.route("/events/<slug>/<section_key>/upload-image", methods=["POST"])
    @login_required
    def upload_section_image(slug, section_key):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            flash("You do not have permission to upload images.")
            return redirect(url_for("event_section", slug=slug, section_key=section_key))

        ensure_default_sections(event["id"])

        file = request.files.get("image")
        if not file or file.filename == "":
            flash("Please choose an image file.")
            return redirect(url_for("event_section", slug=slug, section_key=section_key))

        if not allowed_file(file.filename):
            flash("Allowed image types: png, jpg, jpeg, webp.")
            return redirect(url_for("event_section", slug=slug, section_key=section_key))

        filename = secure_filename(file.filename)
        unique_name = f"{slug}-{section_key}-{secrets.token_hex(6)}-{filename}"

        # Try Drive first (stores URL)
        stored_value = _drive_upload_image_and_get_url(file, unique_name)

        # Local fallback (may disappear on Render redeploy)
        if not stored_value:
            try:
                file.save(os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name))
                stored_value = unique_name
            except Exception as e:
                current_app.logger.exception("Local save failed in upload_section_image. err=%s", e)
                flash("Upload failed.")
                return redirect(url_for("event_section", slug=slug, section_key=section_key))

        db = get_db()
        db.execute(
            """
            UPDATE sections
            SET image=?
            WHERE event_id=? AND section_key=?
            """,
            (stored_value, event["id"], section_key),
        )

        if section_key == "home":
            db.execute("UPDATE events SET cover_image=? WHERE id=?", (stored_value, event["id"]))

        db.commit()

        flash("Image uploaded.")
        return redirect(url_for("event_section", slug=slug, section_key=section_key))

    @app.route("/events/<slug>/<section_key>/toggle", methods=["POST"])
    @login_required
    def toggle_section(slug, section_key):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            flash("You do not have permission to do that.")
            return redirect(url_for("event_section", slug=slug, section_key=section_key))

        ensure_default_sections(event["id"])
        db = get_db()
        sec = db.execute(
            "SELECT * FROM sections WHERE event_id=? AND section_key=?",
            (event["id"], section_key),
        ).fetchone()

        new_visible = 0 if int(sec["visible"]) == 1 else 1
        db.execute(
            "UPDATE sections SET visible=? WHERE event_id=? AND section_key=?",
            (new_visible, event["id"], section_key),
        )
        db.commit()

        flash("Section visibility updated.")
        return redirect(url_for("event_section", slug=slug, section_key=section_key))

    # -------- drafts / publish --------
    @app.route("/events/<slug>/story/draft", methods=["POST"])
    @login_required
    def story_save_draft(slug):
        event = get_event_by_slug(slug)
        if not event:
            return ("Not found", 404)
        if not has_event_view_access(event):
            return ("Forbidden", 403)
        if not can_manage_event(event):
            return ("Forbidden", 403)

        draft_html = sanitize_quill_html(request.form.get("draft_html") or "")
        ensure_default_sections(event["id"])

        db = get_db()
        db.execute(
            """
            UPDATE sections SET draft_content=?
            WHERE event_id=? AND section_key='story'
            """,
            (draft_html, event["id"]),
        )
        db.commit()
        return ("", 204)

    @app.route("/events/<slug>/story/publish", methods=["POST"])
    @login_required
    def story_publish(slug):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            flash("You do not have permission to publish this section.")
            return redirect(url_for("event_section", slug=slug, section_key="story"))

        ensure_default_sections(event["id"])
        db = get_db()
        sec = db.execute(
            "SELECT * FROM sections WHERE event_id=? AND section_key='story'",
            (event["id"],),
        ).fetchone()

        published = (sec["draft_content"] or "") if sec else ""
        db.execute(
            """
            UPDATE sections SET content=?, draft_content=?
            WHERE event_id=? AND section_key='story'
            """,
            (published, published, event["id"]),
        )
        db.commit()

        flash("Story published.")
        return redirect(url_for("event_section", slug=slug, section_key="story"))

    @app.route("/events/<slug>/meet-couple/draft", methods=["POST"])
    @login_required
    def meet_couple_save_draft(slug):
        event = get_event_by_slug(slug)
        if not event:
            return ("Not found", 404)
        if not has_event_view_access(event):
            return ("Forbidden", 403)
        if not can_manage_event(event):
            return ("Forbidden", 403)

        draft_html = sanitize_quill_html(request.form.get("draft_html") or "")
        ensure_default_sections(event["id"])

        db = get_db()
        db.execute(
            """
            UPDATE sections SET draft_content=?
            WHERE event_id=? AND section_key='meet-couple'
            """,
            (draft_html, event["id"]),
        )
        db.commit()
        return ("", 204)

    @app.route("/events/<slug>/meet-couple/publish", methods=["POST"])
    @login_required
    def meet_couple_publish(slug):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            flash("You do not have permission to publish this section.")
            return redirect(url_for("event_section", slug=slug, section_key="meet-couple"))

        ensure_default_sections(event["id"])
        db = get_db()
        sec = db.execute(
            "SELECT * FROM sections WHERE event_id=? AND section_key='meet-couple'",
            (event["id"],),
        ).fetchone()

        published = (sec["draft_content"] or "") if sec else ""
        db.execute(
            """
            UPDATE sections SET content=?, draft_content=?
            WHERE event_id=? AND section_key='meet-couple'
            """,
            (published, published, event["id"]),
        )
        db.commit()

        flash("Meet the Couple published.")
        return redirect(url_for("event_section", slug=slug, section_key="meet-couple"))

    @app.route("/events/<slug>/proposal/draft", methods=["POST"])
    @login_required
    def proposal_save_draft(slug):
        event = get_event_by_slug(slug)
        if not event:
            return ("Not found", 404)
        if not has_event_view_access(event):
            return ("Forbidden", 403)
        if not can_manage_event(event):
            return ("Forbidden", 403)

        draft_html = sanitize_quill_html(request.form.get("draft_html") or "")
        ensure_default_sections(event["id"])

        db = get_db()
        db.execute(
            """
            UPDATE sections SET draft_content=?
            WHERE event_id=? AND section_key='proposal'
            """,
            (draft_html, event["id"]),
        )
        db.commit()
        return ("", 204)

    @app.route("/events/<slug>/proposal/publish", methods=["POST"])
    @login_required
    def proposal_publish(slug):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            flash("You do not have permission to publish this section.")
            return redirect(url_for("event_section", slug=slug, section_key="proposal"))

        ensure_default_sections(event["id"])
        db = get_db()
        sec = db.execute(
            "SELECT * FROM sections WHERE event_id=? AND section_key='proposal'",
            (event["id"],),
        ).fetchone()

        published = (sec["draft_content"] or "") if sec else ""
        db.execute(
            """
            UPDATE sections SET content=?, draft_content=?
            WHERE event_id=? AND section_key='proposal'
            """,
            (published, published, event["id"]),
        )
        db.commit()

        flash("Proposal published.")
        return redirect(url_for("event_section", slug=slug, section_key="proposal"))

    @app.route("/events/<slug>/tidbits/draft", methods=["POST"])
    @login_required
    def tidbits_save_draft(slug):
        import json

        event = get_event_by_slug(slug)
        if not event:
            return ("Not found", 404)
        if not has_event_view_access(event):
            return ("Forbidden", 403)
        if not can_manage_event(event):
            return ("Forbidden", 403)

        raw_json = (request.form.get("draft_json") or "").strip()
        ensure_default_sections(event["id"])

        try:
            data = json.loads(raw_json) if raw_json else []
            if not isinstance(data, list):
                raise ValueError("tidbits must be a list")
            cleaned = []
            for item in data:
                if isinstance(item, dict):
                    q = (item.get("q") or "").strip()
                    a = (item.get("a") or "").strip()
                    cleaned.append({"q": q, "a": a})
            raw_json = json.dumps(cleaned, ensure_ascii=False)
        except Exception:
            return ("Bad Request", 400)

        db = get_db()
        db.execute(
            """
            UPDATE sections SET draft_content=?
            WHERE event_id=? AND section_key='tidbits'
            """,
            (raw_json, event["id"]),
        )
        db.commit()
        return ("", 204)

    @app.route("/events/<slug>/tidbits/publish", methods=["POST"])
    @login_required
    def tidbits_publish(slug):
        import json

        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            flash("You do not have permission to publish this section.")
            return redirect(url_for("event_section", slug=slug, section_key="tidbits"))

        ensure_default_sections(event["id"])

        force_json = (request.form.get("draft_json") or "").strip()
        if not force_json and request.is_json:
            payload = request.get_json(silent=True) or {}
            if isinstance(payload, dict):
                force_json = (payload.get("draft_json") or "").strip()

        db = get_db()
        sec = db.execute(
            "SELECT * FROM sections WHERE event_id=? AND section_key='tidbits'",
            (event["id"],),
        ).fetchone()

        payload_json = (sec["draft_content"] or "[]") if sec else "[]"
        if force_json:
            try:
                parsed = json.loads(force_json)
                cleaned = []
                if isinstance(parsed, list):
                    for item in parsed:
                        if not isinstance(item, dict):
                            continue
                        q = (item.get("q") or item.get("question") or "").strip()
                        a = (item.get("a") or item.get("answer") or "").strip()
                        if q or a:
                            cleaned.append({"q": q, "a": a})
                payload_json = json.dumps(cleaned, ensure_ascii=False)
            except Exception:
                payload_json = (sec["draft_content"] or "[]") if sec else "[]"

        db.execute(
            "UPDATE sections SET content=?, draft_content=? WHERE event_id=? AND section_key='tidbits'",
            (payload_json, payload_json, event["id"]),
        )
        db.commit()

        flash("Tidbits published.")
        return redirect(url_for("event_section", slug=slug, section_key="tidbits"))

    @app.route("/events/<slug>/qa/draft", methods=["POST"])
    @login_required
    def qa_save_draft(slug):
        import json

        event = get_event_by_slug(slug)
        if not event:
            return ("Not found", 404)
        if not has_event_view_access(event):
            return ("Forbidden", 403)
        if not can_manage_event(event):
            return ("Forbidden", 403)

        raw_json = (request.form.get("draft_json") or "").strip()
        ensure_default_sections(event["id"])

        try:
            data = json.loads(raw_json) if raw_json else []
            if not isinstance(data, list):
                raise ValueError("qa must be a list")
            cleaned = []
            for item in data:
                if isinstance(item, dict):
                    q = (item.get("q") or "").strip()
                    a = (item.get("a") or "").strip()
                    cleaned.append({"q": q, "a": a})
            raw_json = json.dumps(cleaned, ensure_ascii=False)
        except Exception:
            return ("Bad Request", 400)

        db = get_db()
        db.execute(
            """
            UPDATE sections SET draft_content=?
            WHERE event_id=? AND section_key='qa'
            """,
            (raw_json, event["id"]),
        )
        db.commit()
        return ("", 204)

    @app.route("/events/<slug>/qa/publish", methods=["POST"])
    @login_required
    def qa_publish(slug):
        import json

        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            flash("You do not have permission to publish this section.")
            return redirect(url_for("event_section", slug=slug, section_key="qa"))

        ensure_default_sections(event["id"])

        force_json = (request.form.get("draft_json") or "").strip()
        if not force_json and request.is_json:
            payload = request.get_json(silent=True) or {}
            if isinstance(payload, dict):
                force_json = (payload.get("draft_json") or "").strip()

        db = get_db()
        sec = db.execute(
            "SELECT * FROM sections WHERE event_id=? AND section_key='qa'",
            (event["id"],),
        ).fetchone()

        payload_json = (sec["draft_content"] or "[]") if sec else "[]"
        if force_json:
            try:
                parsed = json.loads(force_json)
                cleaned = []
                if isinstance(parsed, list):
                    for item in parsed:
                        if not isinstance(item, dict):
                            continue
                        q = (item.get("q") or item.get("question") or "").strip()
                        a = (item.get("a") or item.get("answer") or "").strip()
                        if q or a:
                            cleaned.append({"q": q, "a": a})
                payload_json = json.dumps(cleaned, ensure_ascii=False)
            except Exception:
                payload_json = (sec["draft_content"] or "[]") if sec else "[]"

        db.execute(
            "UPDATE sections SET content=?, draft_content=? WHERE event_id=? AND section_key='qa'",
            (payload_json, payload_json, event["id"]),
        )
        db.commit()

        flash("Q&A published.")
        return redirect(url_for("event_section", slug=slug, section_key="qa"))

    @app.route("/events/<slug>/sections/add", methods=["GET", "POST"])
    @login_required
    def add_section(slug):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            flash("You do not have permission to do that.")
            return redirect(url_for("event_section", slug=slug, section_key="home"))

        ensure_default_sections(event["id"])
        sections = get_event_sections(event["id"])

        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            section_type = (request.form.get("section_type") or "").strip()

            if not name:
                flash("Please enter a section name.")
                return redirect(url_for("add_section", slug=slug))

            if section_type not in ("free_text", "qa"):
                flash("Please choose a valid section type.")
                return redirect(url_for("add_section", slug=slug))

            prefix = "custom-text-" if section_type == "free_text" else "custom-qa-"
            section_key = unique_custom_section_key(event["id"], name, prefix)
            initial_content = "" if section_type == "free_text" else "[]"

            new_sort = _next_sort_order(event["id"])

            db = get_db()
            db.execute(
                """
                INSERT INTO sections(event_id, section_key, title, visible, content, draft_content, image, sort_order)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (event["id"], section_key, name, 1, initial_content, initial_content, "", new_sort),
            )
            db.commit()

            flash("Section added.")
            return redirect(url_for("event_section", slug=slug, section_key=section_key))

        return render_template(
            "event_add_section.html",
            user=current_user(),
            event=event,
            sections=sections,
            section_key="__add__",
            section=sections.get("home"),
            is_admin=True,
        )

    # -------- reorder sections (drag & drop) --------
    @app.route("/events/<slug>/sections/reorder", methods=["POST"])
    @app.route("/events/<slug>/sections/order", methods=["POST"])
    @app.route("/events/<slug>/sections/sort", methods=["POST"])
    @login_required
    def sections_reorder(slug):
        event = get_event_by_slug(slug)
        if not event:
            abort(404)

        if not can_manage_event(event):
            abort(403)

        order = None
        if request.is_json:
            data = request.get_json(silent=True) or {}
            for k in ("order", "keys", "section_keys", "sections"):
                if isinstance(data.get(k), list):
                    order = [str(x) for x in data.get(k)]
                    break
            if order is None and isinstance(data.get("order"), str):
                order = [x.strip() for x in data.get("order").split(",") if x.strip()]

        if order is None:
            order = request.form.getlist("order[]") or request.form.getlist("order") or []
            if len(order) == 1 and isinstance(order[0], str) and "," in order[0]:
                order = [x.strip() for x in order[0].split(",") if x.strip()]

        if not order:
            return ("", 204)

        sections = get_event_sections(event["id"])
        valid = [k for k in order if k in sections]
        for k in sections.keys():
            if k not in valid:
                valid.append(k)

        db = get_db()
        sort = 10
        for k in valid:
            db.execute(
                "UPDATE sections SET sort_order=? WHERE event_id=? AND section_key=?",
                (sort, event["id"], k),
            )
            sort += 10
        db.commit()
        return ("", 204)

    # -------- custom sections drafts / publish --------
    @app.route("/events/<slug>/sections/<section_key>/draft", methods=["POST"])
    @login_required
    def custom_section_save_draft(slug, section_key):
        import json

        event = get_event_by_slug(slug)
        if not event:
            return ("Not found", 404)
        if not has_event_view_access(event):
            return ("Forbidden", 403)
        if not can_manage_event(event):
            return ("Forbidden", 403)

        ensure_default_sections(event["id"])
        db = get_db()
        sec = db.execute(
            "SELECT * FROM sections WHERE event_id=? AND section_key=?",
            (event["id"], section_key),
        ).fetchone()
        if not sec:
            return ("Not found", 404)

        if (sec["section_key"] or "").startswith("custom-qa-"):
            raw_json = (request.form.get("draft_json") or "").strip()
            try:
                data = json.loads(raw_json) if raw_json else []
                if not isinstance(data, list):
                    raise ValueError("qa must be a list")
                cleaned = []
                for item in data:
                    if isinstance(item, dict):
                        q = (item.get("q") or "").strip()
                        a = (item.get("a") or "").strip()
                        if q or a:
                            cleaned.append({"q": q, "a": a})
                raw_json = json.dumps(cleaned, ensure_ascii=False)
            except Exception:
                return ("Bad Request", 400)

            db.execute(
                "UPDATE sections SET draft_content=? WHERE event_id=? AND section_key=?",
                (raw_json, event["id"], section_key),
            )
            db.commit()
            return ("", 204)

        draft_html = sanitize_quill_html(request.form.get("draft_html") or "")
        db.execute(
            "UPDATE sections SET draft_content=? WHERE event_id=? AND section_key=?",
            (draft_html, event["id"], section_key),
        )
        db.commit()
        return ("", 204)

    @app.route("/events/<slug>/sections/<section_key>/publish", methods=["POST"])
    @login_required
    def custom_section_publish(slug, section_key):
        import json

        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            flash("You do not have permission to publish this section.")
            return redirect(url_for("event_section", slug=slug, section_key=section_key))

        ensure_default_sections(event["id"])
        db = get_db()
        sec = db.execute(
            "SELECT * FROM sections WHERE event_id=? AND section_key=?",
            (event["id"], section_key),
        ).fetchone()
        if not sec:
            return render_template("not_found.html", user=current_user()), 404

        force_json = (request.form.get("draft_json") or "").strip()
        if not force_json and request.is_json:
            payload = request.get_json(silent=True) or {}
            if isinstance(payload, dict):
                force_json = (payload.get("draft_json") or "").strip()

        new_content = sec["draft_content"] if sec["draft_content"] is not None else (sec["content"] or "")

        if force_json and ((section_key or "").startswith("custom-qa-")):
            try:
                parsed = json.loads(force_json)
                cleaned = []
                if isinstance(parsed, list):
                    for item in parsed:
                        if not isinstance(item, dict):
                            continue
                        q = (item.get("q") or item.get("question") or "").strip()
                        a = (item.get("a") or item.get("answer") or "").strip()
                        if q or a:
                            cleaned.append({"q": q, "a": a})
                new_content = json.dumps(cleaned, ensure_ascii=False)
            except Exception:
                pass

        db.execute(
            "UPDATE sections SET content=?, draft_content=? WHERE event_id=? AND section_key=?",
            (new_content, new_content, event["id"], section_key),
        )
        db.commit()

        flash("Section published.")
        return redirect(url_for("event_section", slug=slug, section_key=section_key))

    @app.route("/events/<slug>/sections/<section_key>/delete", methods=["POST"])
    @login_required
    def custom_section_delete(slug, section_key):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            flash("You do not have permission to do that.")
            return redirect(url_for("event_section", slug=slug, section_key="home"))

        if not ((section_key or "").startswith("custom-text-") or (section_key or "").startswith("custom-qa-")):
            flash("Only custom sections can be deleted.")
            return redirect(url_for("event_section", slug=slug, section_key=section_key))

        ensure_default_sections(event["id"])
        db = get_db()
        sec = db.execute(
            "SELECT * FROM sections WHERE event_id=? AND section_key=?",
            (event["id"], section_key),
        ).fetchone()
        if not sec:
            flash("Section not found.")
            return redirect(url_for("event_section", slug=slug, section_key="home"))

        try:
            img = (sec["image"] or "").strip()
            if img and (not _is_url(img)):
                path = os.path.join(current_app.config["UPLOAD_FOLDER"], img)
                if os.path.exists(path):
                    os.remove(path)
        except Exception:
            pass

        db.execute(
            "DELETE FROM sections WHERE event_id=? AND section_key=?",
            (event["id"], section_key),
        )
        db.commit()

        flash("Section deleted.")
        return redirect(url_for("event_section", slug=slug, section_key="home"))

    # -------- section router --------
    @app.route("/events/<slug>/<section_key>")
    def event_section(slug, section_key):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404

        if not current_user():
            flash("Please log in to access this event.")
            return redirect(url_for("login", next=url_for("event_gate", slug=slug)))

        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))

        ensure_default_sections(event["id"])
        sections = get_event_sections(event["id"])

        if section_key not in sections:
            return render_template("not_found.html", user=current_user()), 404

        section = sections[section_key]
        real_admin = can_manage_event(event)

        view_as_user = bool(session.get(preview_session_key(slug)))
        if real_admin and (request.args.get("_as_user") == "1"):
            view_as_user = True

        draft_preview = bool(real_admin and (request.args.get("_draft") == "1"))
        is_admin = real_admin and (not view_as_user)

        # Public users (not owner/admin) see the single-page view
        if (not real_admin) and (not view_as_user):
            return redirect(url_for("event_public_all_sections", slug=slug))

        public_preview_url = None
        back_to_editor_url = None
        if real_admin:
            public_preview_url = url_for(
                "event_section", slug=slug, section_key=section_key, _as_user=1, _draft=1
            )
        if view_as_user and real_admin:
            back_to_editor_url = url_for("event_section", slug=slug, section_key=section_key)

        if int(section["visible"]) == 0 and not is_admin:
            return render_template("not_found.html", user=current_user()), 404

        if section_key == "rsvp":
            return redirect(url_for("rsvp_form", slug=slug))
        if section_key == "photos":
            return redirect(url_for("event_photos", slug=slug))
        if section_key == "photos-day":
            return redirect(url_for("photos_day_admin", slug=slug))

        if section_key == "home":
            d = parse_date_iso(event["date_iso"])
            weekday = format_weekday(d) if d else ""
            long_date = format_long_date(d) if d else ""
            countdown_iso = countdown_target_iso(d) if d else ""
            return render_template(
                "event_home.html",
                user=current_user(),
                event=event,
                sections=sections,
                section_key=section_key,
                section=section,
                is_admin=is_admin,
                weekday=weekday,
                long_date=long_date,
                countdown_iso=countdown_iso,
            )

        if section_key == "story":
            return render_template(
                "event_story_editor.html",
                user=current_user(),
                event=event,
                sections=sections,
                section_key=section_key,
                section=section,
                is_admin=is_admin,
                view_as_user=view_as_user,
                draft_preview=draft_preview,
                public_preview_url=public_preview_url,
                back_to_editor_url=back_to_editor_url,
                can_manage=real_admin,
                story_draft=section["draft_content"] or "",
                story_published=section["content"] or "",
            )

        if section_key == "meet-couple":
            return render_template(
                "event_meet_couple_editor.html",
                user=current_user(),
                event=event,
                sections=sections,
                section_key=section_key,
                section=section,
                is_admin=is_admin,
                view_as_user=view_as_user,
                draft_preview=draft_preview,
                public_preview_url=public_preview_url,
                back_to_editor_url=back_to_editor_url,
                can_manage=real_admin,
                meet_draft=section["draft_content"] or "",
                meet_published=section["content"] or "",
            )

        if section_key == "proposal":
            return render_template(
                "event_proposal_editor.html",
                user=current_user(),
                event=event,
                sections=sections,
                section_key=section_key,
                section=section,
                is_admin=is_admin,
                view_as_user=view_as_user,
                draft_preview=draft_preview,
                public_preview_url=public_preview_url,
                back_to_editor_url=back_to_editor_url,
                can_manage=real_admin,
                proposal_draft=section["draft_content"] or "",
                proposal_published=section["content"] or "",
            )

        if section_key == "tidbits":
            draft_items = parse_qa_list_json(section["draft_content"] or "")
            published_items = parse_qa_list_json(section["content"] or "")
            if draft_preview:
                published_items = draft_items
            import json
            return render_template(
                "event_tidbits_editor.html",
                user=current_user(),
                event=event,
                sections=sections,
                section_key=section_key,
                section=section,
                is_admin=is_admin,
                view_as_user=view_as_user,
                draft_preview=draft_preview,
                public_preview_url=public_preview_url,
                back_to_editor_url=back_to_editor_url,
                can_manage=real_admin,
                tidbits_draft_items=draft_items,
                tidbits_published_items=published_items,
                tidbits_draft_json=json.dumps(draft_items, ensure_ascii=False),
                tidbits_published_json=json.dumps(published_items, ensure_ascii=False),
            )

        if section_key == "qa":
            draft_items = parse_qa_list_json(section["draft_content"] or "")
            published_items = parse_qa_list_json(section["content"] or "")
            if draft_preview:
                published_items = draft_items
            import json
            return render_template(
                "event_qa_editor.html",
                user=current_user(),
                event=event,
                sections=sections,
                section_key=section_key,
                section=section,
                is_admin=is_admin,
                view_as_user=view_as_user,
                draft_preview=draft_preview,
                public_preview_url=public_preview_url,
                back_to_editor_url=back_to_editor_url,
                can_manage=real_admin,
                qa_draft_items=draft_items,
                qa_published_items=published_items,
                qa_draft_json=json.dumps(draft_items, ensure_ascii=False),
                qa_published_json=json.dumps(published_items, ensure_ascii=False),
            )

        if (section_key or "").startswith("custom-text-"):
            return render_template(
                "event_section_free_text_editor.html",
                user=current_user(),
                event=event,
                sections=sections,
                section_key=section_key,
                section=section,
                is_admin=is_admin,
                view_as_user=view_as_user,
                draft_preview=draft_preview,
                public_preview_url=public_preview_url,
                back_to_editor_url=back_to_editor_url,
                can_manage=real_admin,
                free_title=section["title"] or "Section",
                free_draft=section["draft_content"] or "",
                free_published=section["content"] or "",
            )

        if (section_key or "").startswith("custom-qa-"):
            draft_items = parse_qa_list_json(section["draft_content"] or "")
            published_items = parse_qa_list_json(section["content"] or "")
            if draft_preview:
                published_items = draft_items
            import json
            return render_template(
                "event_section_qa_editor.html",
                user=current_user(),
                event=event,
                sections=sections,
                section_key=section_key,
                section=section,
                is_admin=is_admin,
                view_as_user=view_as_user,
                draft_preview=draft_preview,
                public_preview_url=public_preview_url,
                back_to_editor_url=back_to_editor_url,
                can_manage=real_admin,
                qa_title=section["title"] or "Q&A",
                qa_draft_items=draft_items,
                qa_published_items=published_items,
                qa_draft_json=json.dumps(draft_items, ensure_ascii=False),
                qa_published_json=json.dumps(published_items, ensure_ascii=False),
            )

        return render_template(
            "event_section.html",
            user=current_user(),
            event=event,
            sections=sections,
            section_key=section_key,
            section=section,
            is_admin=is_admin,
        )

    # -------- public single-page scroll view --------
    @app.route("/events/<slug>/all", endpoint="event_public_all_sections")
    def event_public_all_sections(slug):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404

        if not current_user():
            flash("Please log in to access this event.")
            return redirect(url_for("login", next=url_for("event_gate", slug=slug)))

        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))

        if can_manage_event(event):
            return redirect(url_for("event_section", slug=slug, section_key="home"))

        ensure_default_sections(event["id"])
        sections = get_event_sections(event["id"])

        def row_get(row, key, default=None):
            try:
                if row is None:
                    return default
                if hasattr(row, "keys") and key in row.keys():
                    return row[key]
                return default
            except Exception:
                return default

        order = list(sections.keys())
        public_sections = []
        for key in order:
            s = sections.get(key)
            if not s:
                continue

            if int(row_get(s, "visible", 1) or 0) == 0:
                continue

            title = (row_get(s, "title") or "").strip()
            if not title:
                title = {
                    "home": "Home",
                    "story": "Our Story",
                    "meet-couple": "Meet the Couple",
                    "proposal": "The Proposal",
                    "tidbits": "Tidbits",
                    "qa": "Q&A",
                    "rsvp": "RSVP",
                    "photos": "Photos",
                }.get(key, key.replace("-", " ").title())

            img = (row_get(s, "image") or "").strip()
            if not img:
                img = (event.get("cover_image") or event["cover_image"] or "").strip()

            kind = "html"
            html = row_get(s, "content") or ""
            items = []

            if key in ("tidbits", "qa") or key.startswith("custom-qa-"):
                kind = "qa_list"
                items = parse_qa_list_json(row_get(s, "content") or "[]")
            elif key in ("rsvp", "photos"):
                kind = "link"
            elif key == "home":
                kind = "home"

            public_sections.append(
                {
                    "key": key,
                    "title": title,
                    "image": img,  # url OR local filename
                    "kind": kind,
                    "html": html,
                    "items": items,
                }
            )

        return render_template(
            "event_public_all_sections.html",
            user=current_user(),
            event=event,
            sections=sections,
            public_sections=public_sections,
            is_admin=False,
            can_manage=False,
            view_as_user=False,
            public_single=True,
        )