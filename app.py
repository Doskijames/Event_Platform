# app.py
import os
from flask import Flask, redirect, url_for, render_template, current_app
from dotenv import load_dotenv

load_dotenv()

from db_core import init_db, close_db
from auth_routes import register_auth_routes, current_user
from events_routes import register_event_routes
from photos_routes import register_photo_routes
from rsvp_routes import register_rsvp_routes

# Optional: Drive proxy routes (recommended)
try:
    from drive_media_routes import register_drive_media_routes
except Exception:
    register_drive_media_routes = None


def create_app():
    app = Flask(__name__)

    # SECRET KEY
    app.secret_key = (os.getenv("FLASK_SECRET_KEY", "dev-secret") or "dev-secret").strip()

    # Ensure DB closes cleanly
    app.teardown_appcontext(close_db)

    # Uploads (local fallback)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    upload_folder = os.path.join(BASE_DIR, "static", "uploads")
    os.makedirs(upload_folder, exist_ok=True)
    app.config["UPLOAD_FOLDER"] = upload_folder

    # Routes
    register_auth_routes(app)
    register_event_routes(app)
    register_photo_routes(app)
    register_rsvp_routes(app)

    if register_drive_media_routes:
        register_drive_media_routes(app)

    # ---------- JINJA HELPERS ----------
    @app.context_processor
    def inject_helpers():
        def has_endpoint(name: str) -> bool:
            try:
                return name in current_app.view_functions
            except Exception:
                return False

        return {
            "has_endpoint": has_endpoint,
            "user": current_user(),
        }

    # Root URL → Home
    @app.route("/")
    def index():
        return redirect(url_for("home"))

    # Home landing page (public)
    @app.route("/home")
    def home():
        return render_template("home.html")

    # Init DB schema + seed defaults
    with app.app_context():
        init_db()

    # Media URL helper (local uploads OR full URLs)
    def media_url(value: str) -> str:
        value = (value or "").strip()
        if not value:
            return ""
        if value.startswith("http://") or value.startswith("https://"):
            return value
        return url_for("static", filename=f"uploads/{value}")

    app.jinja_env.globals["media_url"] = media_url

    return app


print(">>> app.py starting")
app = create_app()
print(">>> app created, starting server on http://127.0.0.1:5000")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
