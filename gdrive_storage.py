# gdrive_storage.py (FULL - supports GOOGLE_* and GDRIVE_* env vars + Base64 + returns URLs)
import os
import io
import json
import base64
from typing import Optional, Dict, Any

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.errors import HttpError

SCOPES = ["https://www.googleapis.com/auth/drive"]


def _env_first(*names: str) -> str:
    """Return first non-empty env var value from names."""
    for n in names:
        v = os.getenv(n, "")
        if v and v.strip():
            return v.strip()
    return ""


def _drive_folder_id() -> str:
    """Supports both GOOGLE_DRIVE_FOLDER_ID and GDRIVE_FOLDER_ID."""
    return _env_first("GOOGLE_DRIVE_FOLDER_ID", "GDRIVE_FOLDER_ID")


def _load_service_account_info() -> Dict[str, Any]:
    """
    Loads Google service account JSON from env.

    Recommended on Render:
      - GOOGLE_SERVICE_ACCOUNT_JSON_BASE64 (or GDRIVE_SERVICE_ACCOUNT_JSON_BASE64)

    Supported:
      - GOOGLE_SERVICE_ACCOUNT_JSON
      - GOOGLE_SERVICE_ACCOUNT_JSON_BASE64
      - GDRIVE_SERVICE_ACCOUNT_JSON
      - GDRIVE_SERVICE_ACCOUNT_JSON_BASE64
      - (optional alias) GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON / _BASE64

    IMPORTANT:
      - Do NOT replace \\n with real newlines before json.loads()
        (that causes "Invalid control character" JSON errors).
    """
    raw_b64 = _env_first(
        "GOOGLE_SERVICE_ACCOUNT_JSON_BASE64",
        "GDRIVE_SERVICE_ACCOUNT_JSON_BASE64",
        "GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON_BASE64",
    )
    raw = _env_first(
        "GOOGLE_SERVICE_ACCOUNT_JSON",
        "GDRIVE_SERVICE_ACCOUNT_JSON",
        "GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON",
    )

    if raw_b64:
        try:
            raw = base64.b64decode(raw_b64).decode("utf-8").strip()
        except Exception as e:
            raise RuntimeError(f"Invalid SERVICE_ACCOUNT_JSON_BASE64: {e}")

    if not raw:
        raise RuntimeError(
            "Missing Google service account credentials. "
            "Set GOOGLE_SERVICE_ACCOUNT_JSON_BASE64 (recommended) or GOOGLE_SERVICE_ACCOUNT_JSON, "
            "or the GDRIVE_* equivalents."
        )

    # Parse JSON AS-IS (no newline replacements here!)
    try:
        info = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            "Service account JSON is not valid JSON. "
            "If you pasted the JSON into an env var, it may have been modified. "
            "Use GOOGLE_SERVICE_ACCOUNT_JSON_BASE64 instead. "
            f"Original error: {e}"
        ) from e

    # Normalize private_key only if it's double-escaped (contains literal \\n)
    pk = info.get("private_key")
    if isinstance(pk, str):
        # If pk already has real newlines, leave it.
        # If pk contains literal backslash-n sequences, convert them.
        if "\\n" in pk and "\n" not in pk:
            info["private_key"] = pk.replace("\\n", "\n")

    return info


def drive_enabled() -> bool:
    """True when Drive integration is configured."""
    has_creds = bool(
        _env_first(
            "GOOGLE_SERVICE_ACCOUNT_JSON_BASE64",
            "GDRIVE_SERVICE_ACCOUNT_JSON_BASE64",
            "GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON_BASE64",
            "GOOGLE_SERVICE_ACCOUNT_JSON",
            "GDRIVE_SERVICE_ACCOUNT_JSON",
            "GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON",
        )
    )
    has_folder = bool(_drive_folder_id())
    return has_creds and has_folder


def get_drive_service():
    """Build Drive API service using service account creds."""
    info = _load_service_account_info()
    creds = service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def drive_file_view_url(file_id: str) -> str:
    return f"https://drive.google.com/file/d/{file_id}/view"


def drive_file_embed_url(file_id: str) -> str:
    # Usually best for <img src="...">
    return f"https://drive.google.com/uc?export=view&id={file_id}"


def upload_file_to_drive(
    file_storage,
    filename: str,
    *,
    folder_id: Optional[str] = None,
    make_public: bool = True,
) -> Dict[str, str]:
    """
    Uploads a Flask FileStorage to Google Drive.

    Returns:
      {
        "file_id": "...",
        "view_url": "...",
        "download_url": "..."   # embed-friendly
      }

    Common 404 causes:
      - folder_id is wrong (not a folder id)
      - service account doesn't have permission to that folder
        (share the folder with the service account's client_email as Editor)
    """
    if file_storage is None:
        raise ValueError("file_storage is None")

    if folder_id is None:
        folder_id = _drive_folder_id() or None

    if not folder_id:
        raise RuntimeError("Missing Drive folder ID. Set GOOGLE_DRIVE_FOLDER_ID or GDRIVE_FOLDER_ID.")

    # Read bytes & reset stream for possible fallback save
    data = file_storage.read()
    try:
        file_storage.stream.seek(0)
    except Exception:
        try:
            file_storage.seek(0)
        except Exception:
            pass

    mime_type = getattr(file_storage, "mimetype", None) or "application/octet-stream"

    service = get_drive_service()
    metadata = {"name": filename, "parents": [folder_id]}
    media = MediaIoBaseUpload(io.BytesIO(data), mimetype=mime_type, resumable=False)

    try:
        created = service.files().create(
            body=metadata,
            media_body=media,
            fields="id",
            supportsAllDrives=True,
        ).execute()
    except HttpError as e:
        raise RuntimeError(
            f"Drive upload failed. Check folder_id and folder permissions for the service account. {e}"
        ) from e

    file_id = created["id"]

    if make_public:
        try:
            service.permissions().create(
                fileId=file_id,
                body={"type": "anyone", "role": "reader"},
                fields="id",
                supportsAllDrives=True,
            ).execute()
        except HttpError as e:
            raise RuntimeError(f"Uploaded file but failed to set public permission: {e}") from e

    return {
        "file_id": file_id,
        "view_url": drive_file_view_url(file_id),
        "download_url": drive_file_embed_url(file_id),
    }
