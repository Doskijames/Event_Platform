# drive_media_routes.py
"""
Drive + local media serving helpers.

Why this exists:
- When you deploy on Render, the local filesystem is ephemeral across deploys.
- Older DB rows may store just a filename like "slug-story-xxxx.jpg".
- The browser then requests /static/uploads/<filename> which 404s after a deploy.

Fix:
- Serve /media/<filename> that checks:
  1) local static/uploads (if present), else
  2) Google Drive folder (search by exact filename), then streams via /media/drive/<file_id>

Templates should use media_url(...) from templates/_media.html (updated in this bundle).
"""

from __future__ import annotations

import os
import time
from typing import Optional, Dict, Tuple

from flask import current_app, redirect, url_for, send_from_directory, Response, abort

from gdrive_storage import drive_enabled, get_drive_service, drive_file_embed_url


# Simple in-memory cache: filename -> (file_id, expires_at)
_NAME_CACHE: Dict[str, Tuple[str, float]] = {}
_CACHE_TTL_SECONDS = 60 * 30  # 30 minutes


def _drive_folder_id() -> str:
    return (os.getenv("GOOGLE_DRIVE_FOLDER_ID", "") or "").strip()


def _cache_get(name: str) -> Optional[str]:
    item = _NAME_CACHE.get(name)
    if not item:
        return None
    file_id, exp = item
    if time.time() > exp:
        _NAME_CACHE.pop(name, None)
        return None
    return file_id


def _cache_set(name: str, file_id: str) -> None:
    _NAME_CACHE[name] = (file_id, time.time() + _CACHE_TTL_SECONDS)


def _find_drive_file_id_by_name(filename: str) -> Optional[str]:
    """
    Search the configured Drive folder for an exact filename match.
    Returns file_id or None.
    """
    if not drive_enabled():
        return None

    folder_id = _drive_folder_id()
    if not folder_id:
        return None

    cached = _cache_get(filename)
    if cached:
        return cached

    try:
        service = get_drive_service()
        # Escape single quotes in Drive query
        safe_name = filename.replace("'", r"\'")
        q = f"name='{safe_name}' and '{folder_id}' in parents and trashed=false"
        resp = (
            service.files()
            .list(q=q, pageSize=1, fields="files(id,name,mimeType)")
            .execute()
        )
        files = (resp or {}).get("files") or []
        if not files:
            return None
        file_id = files[0].get("id")
        if file_id:
            _cache_set(filename, file_id)
        return file_id
    except Exception as e:
        current_app.logger.warning("Drive name lookup failed for %s: %s", filename, e)
        return None


def register_drive_media_routes(app):
    """
    Call from app.py:
        from drive_media_routes import register_drive_media_routes
        register_drive_media_routes(app)
    """

    @app.get("/media/drive/<file_id>")
    def media_drive(file_id: str):
        """
        Stream a Drive file through our server so browsers don't get blocked
        by Drive/X-Frame/CORS quirks.
        """
        # IMPORTANT: this endpoint is public read-only
        # We rely on Drive permissions (anyone reader) for access.
        import requests  # requests is available on Render Python images

        url = drive_file_embed_url(file_id)  # uc?export=view&id=...
        try:
            r = requests.get(url, stream=True, timeout=20, allow_redirects=True)
        except Exception as e:
            current_app.logger.warning("Drive proxy request failed: %s", e)
            abort(404)

        if r.status_code != 200:
            current_app.logger.warning("Drive proxy non-200: %s %s", r.status_code, url)
            abort(404)

        content_type = r.headers.get("Content-Type", "application/octet-stream")

        def generate():
            for chunk in r.iter_content(chunk_size=1024 * 64):
                if chunk:
                    yield chunk

        return Response(generate(), content_type=content_type)

    @app.get("/media/<path:filename>")
    def media_by_name(filename: str):
        """
        Preferred way to serve images stored as filenames in DB.
        - First try local static/uploads/<filename>
        - If missing, try Drive lookup by name then redirect to /media/drive/<file_id>
        """
        filename = (filename or "").strip()
        if not filename:
            abort(404)

        # 1) local
        uploads_dir = os.path.join(app.static_folder, "uploads")
        local_path = os.path.join(uploads_dir, filename)
        if os.path.isfile(local_path):
            return send_from_directory(uploads_dir, filename)

        # 2) Drive lookup
        file_id = _find_drive_file_id_by_name(filename)
        if file_id:
            return redirect(url_for("media_drive", file_id=file_id), code=302)

        abort(404)
