# gdrive_storage.py
# Google Drive storage helper for Flask uploads.
#
# Setup required env vars on Render:
# - GOOGLE_SERVICE_ACCOUNT_JSON  (service account json as a single line / raw json)
#   OR GOOGLE_SERVICE_ACCOUNT_FILE (path to json file)
# - GDRIVE_FOLDER_ID             (the Drive folder where uploads will be stored)
#
# Optional:
# - GDRIVE_MAKE_PUBLIC="1"       (default 1) -> shares "anyone with link can view"
#
# Notes:
# - This uses a *service account*. You MUST share your Drive folder with the service
#   account email (Editor access) so it can upload files there.

from __future__ import annotations

import json
import os
from typing import Optional, Tuple, BinaryIO

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload


SCOPES = ["https://www.googleapis.com/auth/drive"]


def drive_enabled() -> bool:
    return bool(_get_folder_id() and (_get_sa_json() or os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")))


def _get_folder_id() -> str:
    return (os.getenv("GDRIVE_FOLDER_ID") or "").strip()


def _get_sa_json() -> Optional[dict]:
    raw = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        # Sometimes users paste JSON with newlines; try to recover
        try:
            return json.loads(raw.replace("\n", "
"))
        except Exception:
            return None


def _get_credentials():
    info = _get_sa_json()
    if info:
        return service_account.Credentials.from_service_account_info(info, scopes=SCOPES)

    path = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")
    if path:
        return service_account.Credentials.from_service_account_file(path, scopes=SCOPES)

    raise RuntimeError("Google Drive credentials not configured")


def _drive_service():
    creds = _get_credentials()
    # cache_discovery=False avoids a warning on some environments
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def _maybe_make_public(service, file_id: str) -> None:
    make_public = (os.getenv("GDRIVE_MAKE_PUBLIC", "1").strip() != "0")
    if not make_public:
        return

    # Allow anyone with the link to read (view) the file
    service.permissions().create(
        fileId=file_id,
        body={"type": "anyone", "role": "reader"},
        fields="id",
    ).execute()


def public_view_url(file_id: str) -> str:
    # Works for images/audio in <img>/<audio> in most cases
    return f"https://drive.google.com/uc?export=view&id={file_id}"


def upload_fileobj(
    fp: BinaryIO,
    filename: str,
    mime_type: str = "application/octet-stream",
    folder_id: Optional[str] = None,
) -> Tuple[str, str]:
    """Uploads a file-like object to Drive.

    Returns: (file_id, public_url)
    """
    folder_id = folder_id or _get_folder_id()
    if not folder_id:
        raise RuntimeError("GDRIVE_FOLDER_ID not set")

    service = _drive_service()

    file_metadata = {"name": filename, "parents": [folder_id]}
    media = MediaIoBaseUpload(fp, mimetype=mime_type, resumable=True)

    created = service.files().create(
        body=file_metadata,
        media_body=media,
        fields="id",
        supportsAllDrives=True,
    ).execute()

    file_id = created["id"]
    _maybe_make_public(service, file_id)

    return file_id, public_view_url(file_id)


def upload_filestorage(file_storage, filename: str, folder_id: Optional[str] = None) -> Tuple[str, str]:
    """Uploads a Werkzeug FileStorage (request.files['...'])"""
    mime_type = getattr(file_storage, "mimetype", None) or "application/octet-stream"
    stream = getattr(file_storage, "stream", None) or file_storage
    return upload_fileobj(stream, filename=filename, mime_type=mime_type, folder_id=folder_id)


# Backwards-compatible helper name used in some routes
def upload_file_to_drive(file_storage, filename: str, folder_id: Optional[str] = None) -> str:
    """Uploads a Flask FileStorage to Drive and returns the public URL."""
    _file_id, url = upload_filestorage(file_storage, filename=filename, folder_id=folder_id)
    return url
