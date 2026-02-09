import os
from datetime import datetime, timezone
from app import app
from db_core import get_db

def main():
    with app.app_context():
        db = get_db()
        now = datetime.now(timezone.utc)

        jobs = db.execute("SELECT id, file_path, expires_at FROM invite_jobs").fetchall() or []
        for j in jobs:
            try:
                exp = datetime.fromisoformat(j["expires_at"])
            except Exception:
                continue

            if exp <= now:
                path = j["file_path"]
                try:
                    if path and os.path.exists(path):
                        os.remove(path)
                except Exception:
                    pass
                db.execute("DELETE FROM invite_jobs WHERE id=?", (j["id"],))

        db.commit()

if __name__ == "__main__":
    main()
