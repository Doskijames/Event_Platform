# rsvp_routes.py  (corrected)
from urllib.parse import quote
import json
from datetime import datetime, timezone
from flask import render_template, request, redirect, url_for, flash, session, make_response

# IMPORTANT: point this to db_core (so you're definitely using the compatible schema)
from db_core import get_db, ensure_default_sections, row_get

from utils_core import has_event_access
from auth_routes import current_user, login_required
from events_routes import get_event_by_slug, get_event_sections, can_manage_event


def register_rsvp_routes(app):
    # WhatsApp double opt-in (click-to-chat confirmation)
    @app.route("/events/<slug>/rsvp/whatsapp/confirm")
    @login_required
    def rsvp_whatsapp_confirm(slug):
        event = get_event_by_slug(slug)
        if not event:
            return ("Not found", 404)
        if not has_event_access(slug):
            return ("Forbidden", 403)

        # Mark confirmation in session; RSVP POST will enforce this before storing opt-in.
        session[f"wa_opt_in_confirmed::{slug}"] = True

        # E-accesslink WhatsApp number (digits only, country code included)
        eaccesslink_phone = "2348084300984"

        msg = "Saying this to confirm that I am giving E-accesslink permission to send WhatsApp messages to me."
        return redirect(f"https://wa.me/{eaccesslink_phone}?text={quote(msg)}")

    @app.route("/events/<slug>/rsvp/questions")
    @login_required
    def rsvp_questions(slug):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_access(slug):
            return redirect(url_for("event_gate", slug=slug))
        if not can_manage_event(event):
            return ("Forbidden", 403)

        ensure_default_sections(event["id"])
        sections = get_event_sections(event["id"])
        section_key = "rsvp"
        section = sections.get("rsvp")

        rows = get_db().execute(
            """
            SELECT * FROM rsvp_questions
            WHERE event_id=?
            ORDER BY position ASC
            """,
            (event["id"],),
        ).fetchall()

        questions = []
        for r in rows:
            try:
                opts = json.loads(r["options"] or "[]")
                if not isinstance(opts, list):
                    opts = []
            except Exception:
                opts = []
            questions.append(
                {
                    "id": r["id"],
                    "position": r["position"],
                    "question": r["question"],
                    "kind": r["kind"] if "kind" in r.keys() else "main",
                    "type": r["type"],
                    "allow_multi": int(r["allow_multi"]) == 1 if "allow_multi" in r.keys() else False,
                    "options": opts,
                    "required": int(r["required"]) == 1,
                    "show_if_question": r["show_if_question"],
                    "show_if_value": r["show_if_value"] or "",
                }
            )

        return render_template(
            "event_rsvp_questions.html",
            user=current_user(),
            event=event,
            sections=sections,
            section_key=section_key,
            section=section,
            is_admin=True,
            questions=questions,
        )

    @app.route("/events/<slug>/rsvp/questions/save", methods=["POST"])
    @login_required
    def rsvp_questions_save(slug):
        event = get_event_by_slug(slug)
        if not event:
            return ("Not found", 404)
        if not has_event_access(slug):
            return ("Forbidden", 403)
        if not can_manage_event(event):
            return ("Forbidden", 403)

        raw = request.form.get("questions_json") or "[]"
        try:
            data = json.loads(raw)
            if not isinstance(data, list):
                return ("Bad Request", 400)
        except Exception:
            return ("Bad Request", 400)

        db = get_db()
        db.execute("DELETE FROM rsvp_questions WHERE event_id=?", (event["id"],))

        pos = 1
        for q in data:
            if not isinstance(q, dict):
                continue

            question = (q.get("question") or "").strip()
            qkind = (q.get("kind") or "main").strip()
            qtype = (q.get("type") or "text").strip()
            required = 1 if bool(q.get("required", True)) else 0
            allow_multi = 1 if bool(q.get("allow_multi", False)) else 0

            options = q.get("options", [])
            if not isinstance(options, list):
                options = []
            options = [(str(x)).strip() for x in options if str(x).strip()]

            show_if_question = q.get("show_if_question")
            if show_if_question in ("", None):
                show_if_question = None
            else:
                try:
                    show_if_question = int(show_if_question)
                except Exception:
                    show_if_question = None

            show_if_value = (q.get("show_if_value") or "").strip()

            if not question:
                continue
            if qkind not in ("main", "followup"):
                qkind = "main"
            if qtype not in ("text", "choice", "number"):
                qtype = "text"

            db.execute(
                """
                INSERT INTO rsvp_questions
                (event_id, position, question, kind, type, allow_multi, options, required, show_if_question, show_if_value)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event["id"],
                    pos,
                    question,
                    qkind,
                    qtype,
                    allow_multi,
                    json.dumps(options, ensure_ascii=False),
                    required,
                    show_if_question,
                    show_if_value,
                ),
            )
            pos += 1

        db.commit()
        return ("", 204)

    @app.route("/events/<slug>/rsvp", methods=["GET", "POST"])
    @login_required
    def rsvp_form(slug):
        event = get_event_by_slug(slug)
        if not event:
            return render_template("not_found.html", user=current_user()), 404
        if not has_event_access(slug):
            return redirect(url_for("event_gate", slug=slug))

        ensure_default_sections(event["id"])
        sections = get_event_sections(event["id"])
        section_key = "rsvp"
        section = sections.get("rsvp")
        is_admin = can_manage_event(event)

        db = get_db()
        rows = db.execute(
            """
            SELECT * FROM rsvp_questions
            WHERE event_id=?
            ORDER BY position ASC
            """,
            (event["id"],),
        ).fetchall()

        questions = []
        for r in rows:
            try:
                opts = json.loads(r["options"] or "[]")
                if not isinstance(opts, list):
                    opts = []
            except Exception:
                opts = []
            questions.append(
                {
                    "position": r["position"],
                    "question": r["question"],
                    "kind": r["kind"] if "kind" in r.keys() else "main",
                    "type": r["type"],
                    "allow_multi": int(r["allow_multi"]) == 1 if "allow_multi" in r.keys() else False,
                    "options": opts,
                    "required": int(r["required"]) == 1,
                    "show_if_question": r["show_if_question"],
                    "show_if_value": r["show_if_value"] or "",
                }
            )

        if request.method == "POST":
            first = (request.form.get("first_name") or "").strip()
            last = (request.form.get("last_name") or "").strip()
            cc = (request.form.get("country_code") or "").strip()
            phone10 = (request.form.get("whatsapp_10") or "").strip()

            # WhatsApp opt-in: user must tick checkbox AND click "Confirm on WhatsApp"
            wants_opt_in = request.form.get("whatsapp_opt_in") == "1"
            confirmed = bool(session.pop(f"wa_opt_in_confirmed::{slug}", False))
            if wants_opt_in and not confirmed:
                flash(
                    "To opt in for WhatsApp updates, please click 'Confirm on WhatsApp' and press Send, then submit the RSVP form.",
                    "error",
                )
                return redirect(url_for("rsvp_form", slug=slug))

            whatsapp_opt_in = 1 if (wants_opt_in and confirmed) else 0
            whatsapp_opt_in_at = datetime.now(timezone.utc).isoformat() if whatsapp_opt_in else ""
            whatsapp_opt_in_source = "rsvp_whatsapp_confirm" if whatsapp_opt_in else ""
            whatsapp_consent_version = (request.form.get("whatsapp_consent_version") or "v1").strip()

            if not first or not last:
                flash("First and Last name are required.")
                return redirect(url_for("rsvp_form", slug=slug))

            if not cc.startswith("+"):
                flash("Please choose a valid country code.")
                return redirect(url_for("rsvp_form", slug=slug))

            if (not phone10.isdigit()) or (len(phone10) != 10):
                flash("WhatsApp number must be exactly 10 digits (excluding country code).")
                return redirect(url_for("rsvp_form", slug=slug))

            whatsapp = f"{cc}{phone10}"
            answers = {}

            def condition_matches(parent_value: str, cond_value: str) -> bool:
                parent_value = (parent_value or "").strip()
                cond_value = (cond_value or "").strip()
                if not cond_value:
                    return True
                parts = [p.strip() for p in cond_value.split("|") if p.strip()]
                return parent_value in parts

            def is_visible(q_pos: int) -> bool:
                q = questions[q_pos - 1]
                cond_q = q.get("show_if_question")
                cond_v = q.get("show_if_value") or ""
                if not cond_q:
                    return True
                parent_val = (request.form.get(f"q_{cond_q}") or "").strip()
                return condition_matches(parent_val, cond_v)

            for idx, _q in enumerate(questions, start=1):
                if not is_visible(idx):
                    answers[f"question_{idx}"] = ""
                    continue

                if _q.get("type") == "choice" and _q.get("allow_multi"):
                    vals = request.form.getlist(f"q_{idx}")
                    vals = [v.strip() for v in vals if v and v.strip()]
                    answers[f"question_{idx}"] = ", ".join(vals)
                else:
                    val = (request.form.get(f"q_{idx}") or "").strip()
                    answers[f"question_{idx}"] = val

            # ✅ FIX: provide all 12 values matching the 12 placeholders
            db.execute(
                """
                INSERT INTO rsvp_responses
                (event_id, user_id, first_name, last_name, email, whatsapp,
                 whatsapp_opt_in, whatsapp_opt_in_at, whatsapp_opt_in_source, whatsapp_consent_version,
                 answers, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event["id"],
                    current_user()["id"],
                    first,
                    last,
                    current_user()["email"],
                    whatsapp,
                    whatsapp_opt_in,
                    whatsapp_opt_in_at,
                    whatsapp_opt_in_source,
                    whatsapp_consent_version,
                    json.dumps(answers, ensure_ascii=False),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            db.commit()

            flash("RSVP submitted successfully ❤️")
            return redirect(url_for("event_section", slug=slug, section_key="home"))

        return render_template(
            "event_rsvp_form.html",
            user=current_user(),
            event=event,
            sections=sections,
            section_key=section_key,
            section=section,
            is_admin=is_admin,
            questions=questions,
        )

    @app.route("/events/<slug>/rsvp/responses")
    @login_required
    def rsvp_responses_view(slug):
        event = get_event_by_slug(slug)
        if not event:
            return ("Not found", 404)
        if not has_event_access(slug):
            return ("Forbidden", 403)
        if not can_manage_event(event):
            return ("Forbidden", 403)

        ensure_default_sections(event["id"])
        sections = get_event_sections(event["id"])
        section_key = "rsvp"
        section = sections.get("rsvp")

        db = get_db()
        q_rows = db.execute(
            "SELECT * FROM rsvp_questions WHERE event_id=? ORDER BY position ASC",
            (event["id"],),
        ).fetchall()
        questions = [dict(r) for r in q_rows]

        resp_rows = db.execute(
            "SELECT * FROM rsvp_responses WHERE event_id=? ORDER BY id DESC",
            (event["id"],),
        ).fetchall()

        responses = []
        for row in resp_rows:
            try:
                answers = json.loads(row_get(row, "answers", "{}") or "{}")
                if not isinstance(answers, dict):
                    answers = {}
            except Exception:
                answers = {}
            responses.append({"row": row, "answers": answers})

        return render_template(
            "event_rsvp_responses.html",
            user=current_user(),
            event=event,
            sections=sections,
            section_key=section_key,
            section=section,
            is_admin=True,
            questions=questions,
            responses=responses,
        )

    @app.route("/events/<slug>/rsvp/responses.csv")
    @login_required
    def rsvp_responses_export_csv(slug):
        event = get_event_by_slug(slug)
        if not event:
            return ("Not found", 404)
        if not has_event_access(slug):
            return ("Forbidden", 403)
        if not can_manage_event(event):
            return ("Forbidden", 403)

        db = get_db()
        q_rows = db.execute(
            "SELECT * FROM rsvp_questions WHERE event_id=? ORDER BY position ASC",
            (event["id"],),
        ).fetchall()
        questions = [dict(r) for r in q_rows]

        resp_rows = db.execute(
            "SELECT * FROM rsvp_responses WHERE event_id=? ORDER BY id DESC",
            (event["id"],),
        ).fetchall()

        import csv, io

        output = io.StringIO()
        writer = csv.writer(output)

        header = ["submitted_at", "first_name", "last_name", "email", "whatsapp", "whatsapp_opt_in"]
        for i, q in enumerate(questions, start=1):
            label = (q.get("label") or q.get("question") or "").strip()
            header.append(f"Q{i} {label}".strip())
        writer.writerow(header)

        for row in resp_rows:
            try:
                answers = json.loads(row_get(row, "answers", "{}") or "{}")
                if not isinstance(answers, dict):
                    answers = {}
            except Exception:
                answers = {}

            opt_in = int(row_get(row, "whatsapp_opt_in", 0) or 0)

            rec = [
                row_get(row, "created_at", ""),
                row_get(row, "first_name", ""),
                row_get(row, "last_name", ""),
                row_get(row, "email", ""),
                row_get(row, "whatsapp", ""),
                "Yes" if opt_in == 1 else "No",
            ]

            for q in questions:
                pos = q.get("position")
                key = f"question_{pos}" if pos is not None else ""
                a = answers.get(key, "")
                if isinstance(a, list):
                    a = ", ".join([str(x) for x in a])
                rec.append(a)

            writer.writerow(rec)

        csv_data = output.getvalue()
        output.close()

        filename = f"{event['slug']}_rsvp_responses.csv"
        resp = make_response(csv_data)
        resp.headers["Content-Type"] = "text/csv; charset=utf-8"
        resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return resp
