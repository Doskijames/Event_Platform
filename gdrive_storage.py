# gdrive_storage.py
import os
import io
import json
import base64
from typing import Optional, Dict, Any, Tuple

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload


SCOPES = ["https://www.googleapis.com/auth/drive"]


def _load_service_account_info() -> Dict[str, Any]:
    """
    Loads Google service account JSON from env.

    Supported env vars (choose ONE):
    - GOOGLE_SERVICE_ACCOUNT_JSON: raw JSON string
    - GOOGLE_SERVICE_ACCOUNT_JSON_BASE64: base64 encoded JSON string

    Handles private_key formatting where newlines are stored as '\\n'.
    """
    raw_b64 = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON_BASE64", "").strip()
    raw = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "").strip()

    if raw_b64:
        try:
            decoded = base64.b64decode(raw_b64).decode("utf-8")
            raw = decoded.strip()
        except Exception as e:
            raise RuntimeError(f"Invalid GOOGLE_SERVICE_ACCOUNT_JSON_BASE64: {e}")

    if not raw:
        raise RuntimeError(
            "Missing Google service account credentials. "
            "Set GOOGLE_SERVICE_ACCOUNT_JSON or GOOGLE_SERVICE_ACCOUNT_JSON_BASE64."
        )

    # If the JSON is stored with escaped newlines in private_key, fix it
    # (this is the most common Render/ENV formatting issue)
    raw_fixed = raw.replace("\\n", "\n")

    try:
        info = json.loads(raw_fixed)
    except Exception as e:
        raise RuntimeError(f"GOOGLE_SERVICE_ACCOUNT_JSON is not valid JSON: {e}")

    # Also ensure private_key has real newlines if present
    pk = info.get("private_key")
    if isinstance(pk, str):
        info["private_key"] = pk.replace("\\n", "\n")

    return info


def drive_enabled() -> bool:
    """
    Returns True when Drive integration is properly configured.
    """
    has_creds = bool(
        (os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "").strip())
        or (os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON_BASE64", "").strip())
    )
    has_folder = bool(os.getenv("GOOGLE_DRIVE_FOLDER_ID", "").strip())
    return has_creds and has_folder


def get_drive_service():
    """
    Builds a Google Drive API service using service account credentials.
    """
    info = _load_service_account_info()
    creds = service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def drive_file_view_url(file_id: str) -> str:
    return f"https://drive.google.com/file/d/{file_id}/view"


def upload_file_to_drive(
    *,
    filename: str,
    file_bytes: bytes,
    mime_type: str = "application/octet-stream",
    folder_id: Optional[str] = None,
    make_public: bool = True,
) -> Dict[str, str]:
    """
    Uploads bytes to Google Drive. Returns:
      { "file_id": "...", "view_url": "...", "download_url": "..." }

    Notes:
    - If make_public=True, sets "anyone with the link can read".
      This is useful for publicly-viewable images in templates.
    """
    if not folder_id:
        folder_id = os.getenv("GOOGLE_DRIVE_FOLDER_ID", "").strip() or None
    if not folder_id:
        raise RuntimeError("Missing GOOGLE_DRIVE_FOLDER_ID")

    service = get_drive_service()

    metadata = {"name": filename, "parents": [folder_id]}
    media = MediaIoBaseUpload(io.BytesIO(file_bytes), mimetype=mime_type, resumable=False)

    created = service.files().create(
        body=metadata,
        media_body=media,
        fields="id, webViewLink, webContentLink",
        supportsAllDrives=True,
    ).execute()

    file_id = created["id"]

    if make_public:
        # Public read permission (anyone with link)
        service.permissions().create(
            fileId=file_id,
            body={"type": "anyone", "role": "reader"},
            fields="id",
            supportsAllDrives=True,
        ).execute()

    # webViewLink might exist depending on response; we also provide a stable URL
    view_url = created.get("webViewLink") or drive_file_view_url(file_id)
    download_url = created.get("webContentLink") or f"https://drive.google.com/uc?id={file_id}&export=download"

    return {
        "file_id": file_id,
        "view_url": view_url,
        "download_url": download_url,
    }


def upload_filestorage_to_drive(
    file_storage,
    *,
    filename: Optional[str] = None,
    folder_id: Optional[str] = None,
    make_public: bool = True,
) -> Dict[str, str]:
    """
    Convenience wrapper for Flask's FileStorage (request.files['...']).
    """
    if file_storage is None:
        raise ValueError("file_storage is None")

    data = file_storage.read()
    # reset stream so Flask doesn't get confused if reused
    try:
        file_storage.stream.seek(0)
    except Exception:
        pass

    final_name = filename or getattr(file_storage, "filename", None) or "upload.bin"
    mime_type = getattr(file_storage, "mimetype", None) or "application/octet-stream"

    return upload_file_to_drive(
        filename=final_name,
        file_bytes=data,
        mime_type=mime_type,
        folder_id=folder_id,
        make_public=make_public,
    )
