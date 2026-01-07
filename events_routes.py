import os
import secrets
from datetime import datetime, timezone, datetime as dt_cls
from functools import wraps

from flask import (
    render_template, request, redirect, url_for,
    session, flash, abort, current_app
)
from werkzeug.utils import secure_filename

from db_core import get_db, ensure_default_sections
from utils_core import (
    slugify, unique_slug, sanitize_quill_html,
    parse_qa_list_json, has_event_access, event_session_key
)
from auth_routes import current_user, login_required

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def get_event_by_slug(slug: str):
    return get_db().execute("SELECT * FROM events WHERE slug=?", (slug,)).fetchone()

def get_event_sections(event_id: int):
    rows = get_db().execute("SELECT * FROM sections WHERE event_id=? ORDER BY sort_order ASC, id ASC", (event_id,)).fetchall()
    return {r["section_key"]: r for r in rows}

def can_manage_event(event_row) -> bool:
    u = current_user()
    if not u:
        return False
    if (u["role"] or "").lower() == "admin":
        return True
    if event_row["owner_user_id"] and int(event_row["owner_user_id"]) == int(u["id"]):
        return True
    return False


def has_event_view_access(event_row) -> bool:
    """Enforce passcode access for event viewing.

    Rules:
    - Owner/admin can always view.
    - If passcode is empty/whitespace => event is public.
    - If passcode is set => viewer must have unlocked it in this browser session.
    """
    if not event_row:
        return False

    # Owner/admin always allowed
    if can_manage_event(event_row):
        return True

    passcode = (event_row["passcode"] or "").strip()
    if not passcode:
        return True

    # Session unlock keyed by event id (stable)
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
    """Create a unique section_key for an event.

    Option B design: custom sections are identified by prefixes:
      - custom-text-*
      - custom-qa-*
    """
    base = slugify(title)
    base = base[:40]  # keep keys readable and short
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

def register_event_routes(app):

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
            db.execute("""
                INSERT INTO events(slug, name, date_iso, location, description, passcode, owner_user_id, cover_image, created_at)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (slug, name, date_iso, location, description, passcode, u["id"], "", now))
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
            if passcode == event["passcode"]:
                session[event_session_key(event["id"])] = True
                return redirect(url_for("event_section", slug=slug, section_key="home"))
            flash("Incorrect passcode. Please try again.")

        return render_template("event_login.html", user=current_user(), event=event)

    @app.route("/events/<slug>/logout")
    def event_logout(slug):
        event = get_event_by_slug(slug)
        if event:
            session.pop(event_session_key(event["id"]), None)
        # Backward-compatible cleanup (older builds stored by slug)
        session.pop(f"event_{slug}", None)
        return redirect(url_for("events"))

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
        file.save(os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name))

        db = get_db()
        db.execute("""
            UPDATE sections
            SET image=?
            WHERE event_id=? AND section_key=?
        """, (unique_name, event["id"], section_key))

        if section_key == "home":
            db.execute("UPDATE events SET cover_image=? WHERE id=?", (unique_name, event["id"]))

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
            (event["id"], section_key)
        ).fetchone()

        new_visible = 0 if int(sec["visible"]) == 1 else 1
        db.execute(
            "UPDATE sections SET visible=? WHERE event_id=? AND section_key=?",
            (new_visible, event["id"], section_key)
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
        db.execute("""
            UPDATE sections SET draft_content=?
            WHERE event_id=? AND section_key='story'
        """, (draft_html, event["id"]))
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
            (event["id"],)
        ).fetchone()

        published = sec["draft_content"] or ""
        # Keep draft_content in sync so draft public preview works after publish
        db.execute("""
            UPDATE sections SET content=?, draft_content=?
            WHERE event_id=? AND section_key='story'
        """, (published, published, event["id"]))
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
        db.execute("""
            UPDATE sections SET draft_content=?
            WHERE event_id=? AND section_key='meet-couple'
        """, (draft_html, event["id"]))
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
            (event["id"],)
        ).fetchone()

        published = sec["draft_content"] or ""
        db.execute("""
            UPDATE sections SET content=?, draft_content=?
            WHERE event_id=? AND section_key='meet-couple'
        """, (published, published, event["id"]))
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
        db.execute("""
            UPDATE sections SET draft_content=?
            WHERE event_id=? AND section_key='proposal'
        """, (draft_html, event["id"]))
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
            (event["id"],)
        ).fetchone()

        published = sec["draft_content"] or ""
        db.execute("""
            UPDATE sections SET content=?, draft_content=?
            WHERE event_id=? AND section_key='proposal'
        """, (published, published, event["id"]))
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
        db.execute("""
            UPDATE sections SET draft_content=?
            WHERE event_id=? AND section_key='tidbits'
        """, (raw_json, event["id"]))
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
            (event["id"],)
        ).fetchone()

        payload_json = sec["draft_content"] or "[]"
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
                payload_json = sec["draft_content"] or "[]"

        # ✅ IMPORTANT FIX: keep draft_content in sync with content (do not clear)
        db.execute(
            "UPDATE sections SET content=?, draft_content=? WHERE event_id=? AND section_key='tidbits'",
            (payload_json, payload_json, event["id"])
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
        db.execute("""
            UPDATE sections SET draft_content=?
            WHERE event_id=? AND section_key='qa'
        """, (raw_json, event["id"]))
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
            (event["id"],)
        ).fetchone()

        payload_json = sec["draft_content"] or "[]"
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
                payload_json = sec["draft_content"] or "[]"

        # ✅ IMPORTANT FIX: keep draft_content in sync with content (do not clear)
        db.execute(
            "UPDATE sections SET content=?, draft_content=? WHERE event_id=? AND section_key='qa'",
            (payload_json, payload_json, event["id"])
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

            db = get_db()
            db.execute(
                """
                INSERT INTO sections(event_id, section_key, title, visible, content, draft_content, image)
                VALUES (?,?,?,?,?,?,?)
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
        """
        Persist section order from the drag-and-drop UI.

        Accepts multiple payload shapes for compatibility:
          - JSON: {"order": ["home","story",...]} or {"keys":[...]} or {"section_keys":[...]}
          - form: order=comma,separated or order[]=key1&order[]=key2
        """
        event = get_event_by_slug(slug)
        if not event:
            abort(404)

        if not can_manage_event(event):
            abort(403)

        # parse payload
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
            # form payload
            order = request.form.getlist("order[]") or request.form.getlist("order") or []
            if len(order) == 1 and isinstance(order[0], str) and "," in order[0]:
                order = [x.strip() for x in order[0].split(",") if x.strip()]

        if not order:
            return ("", 204)

        # Validate: keep only keys that belong to this event
        sections = get_event_sections(event["id"])  # ordered dict
        valid = [k for k in order if k in sections]

        # also include any sections not present in payload (append at end, keep existing relative order)
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

        # ✅ IMPORTANT FIX: keep draft_content in sync with content (do not clear)
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
            if img:
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

        # Public users (not event owner/admin) should see the single-page, scrollable view
        if (not real_admin) and (not view_as_user):
            return redirect(url_for("event_public_all_sections", slug=slug))

        public_preview_url = None
        back_to_editor_url = None
        if real_admin:
            public_preview_url = url_for("event_section", slug=slug, section_key=section_key, _as_user=1, _draft=1)
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
    @app.route("/events/<slug>/all")
    def event_public_all_sections(slug):
        """Public, single-page view that stacks all visible sections and uses anchor navigation.
        Admins/owners keep the existing per-section UX.
        """
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404

        # must be logged in to view events (same policy as per-section)
        if not current_user():
            flash("Please log in to access this event.")
            return redirect(url_for("login", next=url_for("event_gate", slug=slug)))

        # enforce passcode unlock rules
        if not has_event_view_access(event):
            return redirect(url_for("event_gate", slug=slug))

        # admins/owners should stay on the normal UX
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

        # Public view should mirror persisted drag-and-drop order.
        # get_event_sections() is ordered by sort_order ASC, id ASC and dict preserves insertion order.
        order = list(sections.keys())
        public_sections = []
        for key in order:
            s = sections.get(key)
            if not s:
                continue

            # skip hidden sections for public users
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

            # image fallback: section image -> event cover image
            img = (row_get(s, "image") or "").strip()
            if not img:
                img = (event["cover_image"] or "").strip()

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

            public_sections.append({
                "key": key,
                "title": title,
                "image": img,
                "kind": kind,
                "html": html,
                "items": items,
            })

        return render_template(
            "event_public_all_sections.html",
            user=current_user(),
            event=event,
            sections=sections,
            public_sections=public_sections,
            is_admin=False,
            view_as_user=False,
            public_single=True,
        )

