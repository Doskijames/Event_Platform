import os
from flask import Flask, redirect, url_for, render_template, current_app
from dotenv import load_dotenv

load_dotenv()

from db_core import init_db, ensure_default_admin, close_db
from auth_routes import register_auth_routes, current_user  # ✅ import current_user
from events_routes import register_event_routes
from photos_routes import register_photo_routes
from rsvp_routes import register_rsvp_routes


def create_app():
    app = Flask(__name__)

    # SECRET KEY
    app.secret_key = (os.getenv("FLASK_SECRET_KEY", "dev-secret") or "dev-secret").strip()

    # DATABASE
    db_path = (os.getenv("DATABASE_PATH", "app.db") or "app.db").strip()
    app.config["DATABASE"] = os.path.abspath(db_path)
    print("✅ DATABASE:", app.config["DATABASE"])

    # Uploads
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    upload_folder = os.path.join(BASE_DIR, "static", "uploads")
    os.makedirs(upload_folder, exist_ok=True)
    app.config["UPLOAD_FOLDER"] = upload_folder

    # Ensure DB closes cleanly
    app.teardown_appcontext(close_db)

    # Routes
    register_auth_routes(app)
    register_event_routes(app)
    register_photo_routes(app)
    register_rsvp_routes(app)

    # ---------- JINJA HELPERS (SAFE) ----------
    @app.context_processor
    def inject_helpers():
        def has_endpoint(name: str) -> bool:
            try:
                return name in current_app.view_functions
            except Exception:
                return False

        # ✅ user is now available in EVERY template (home included)
        return {
            "has_endpoint": has_endpoint,
            "user": current_user()
        }

    # Root URL → Home
    @app.route("/")
    def index():
        return redirect(url_for("home"))

    # Home landing page (public)
    @app.route("/home")
    def home():
        return render_template("home.html")

    # Init DB + ensure default admin
    with app.app_context():
        init_db()
        ensure_default_admin()

    return app


print(">>> app.py starting")
app = create_app()
print(">>> app created, starting server on http://127.0.0.1:5000")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
