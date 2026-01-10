# drive_media_routes.py
# Serves Google Drive-hosted images via YOUR domain so <img> tags work reliably.
#
# Route:
#   GET /media/drive/<file_id>
#
# It fetches the bytes from Google Drive "uc" endpoint and streams them back
# with a safe Content-Type and caching headers.

from __future__ import annotations

import re
import requests
from flask import Response

_FILE_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{10,}$")


def register_drive_media_routes(app):
    @app.get("/media/drive/<file_id>")
    def media_drive(file_id: str):
        file_id = (file_id or "").strip()
        if not file_id or not _FILE_ID_RE.match(file_id):
            return ("Bad file id", 400)

        # "download" is more reliable for raw bytes.
        upstream = f"https://drive.google.com/uc?export=download&id={file_id}"

        try:
            r = requests.get(upstream, stream=True, timeout=20)
        except Exception:
            return ("Upstream fetch failed", 502)

        if r.status_code != 200:
            return (f"Drive returned {r.status_code}", 502)

        content_type = r.headers.get("Content-Type") or "application/octet-stream"

        def generate():
            try:
                for chunk in r.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        yield chunk
            finally:
                r.close()

        resp = Response(generate(), content_type=content_type)
        resp.headers["Cache-Control"] = "public, max-age=86400"
        return resp

    return app
