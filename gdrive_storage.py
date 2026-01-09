# gdrive_storage.py (FULL - supports GOOGLE_* and GDRIVE_* env vars)
import os
import io
import json
import base64
from typing import Optional, Dict, Any

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

SCOPES = ["https://www.googleapis.com/auth/drive"]


def _env_first(*names: str) -> str:
    """
    Returns the first non-empty environment variable value from the provided names.
    """
    for n in names:
        v = os.getenv(n, "")
        if v and v.strip():
            return v.strip()
    return ""


def _load_service_account_info() -> Dict[str, Any]:
    """
    Loads Google service account JSON from env.

    Supported env vars (choose ONE):
    - GOOGLE_SERVICE_ACCOUNT_JSON: raw JSON string
    - GOOGLE_SERVICE_ACCOUNT_JSON_BASE64: base64 encoded JSON string

    Also supports legacy/alternate names:
    - GDRIVE_SERVICE_ACCOUNT_JSON
    - GDRIVE_SERVICE_ACCOUNT_JSON_BASE64

    Handles private_key formatting where newlines are stored as '\\n'.
    """
    raw_b64 = _env_first(
        "GOOGLE_SERVICE_ACCOUNT_JSON_BASE64",
        "GDRIVE_SERVICE_ACCOUNT_JSON_BASE64",
    )
    raw = _env_first(
        "GOOGLE_SERVICE_ACCOUNT_JSON",
        "GDRIVE_SERVICE_ACCOUNT_JSON",
    )

    if raw_b64:
        try:
            decoded = base64.b64decode(raw_b64).decode("utf-8")
            raw = decoded.strip()
        except Exception as e:
            raise RuntimeError(f"Invalid SERVICE_ACCOUNT_JSON_BASE64: {e}")

    if not raw:
        raise RuntimeError(
            "Missing Google service account credentials. "
            "Set GOOGLE_SERVICE_ACCOUNT_JSON / GOOGLE_SERVICE_ACCOUNT_JSON_BASE64 "
            "or GDRIVE_SERVICE_ACCOUNT_JSON / GDRIVE_SERVICE_ACCOUNT_JSON_BASE64."
        )

    # Fix common ENV escaping issues
    raw_fixed = raw.replace("\\n", "\n")

    try:
        info = json.loads(raw_fixed)
    except Exception as e:
        raise RuntimeError(f"Service account JSON is not valid JSON: {e}")

    pk = info.get("private_key")
    if isinstance(pk, str):
        info["private_key"] = pk.replace("\\n", "\n")

    return info


def _drive_folder_id() -> str:
    """
    Supports both GOOGLE_DRIVE_FOLDER_ID and GDRIVE_FOLDER_ID.
    """
    return _env_first("GOOGLE_DRIVE_FOLDER_ID", "GDRIVE_FOLDER_ID")


def drive_enabled() -> bool:
    """
    Returns True when Drive integration is properly configured.
    """
    has_creds = bool(
        _env_first(
            "GOOGLE_SERVICE_ACCOUNT_JSON",
            "GDRIVE_SERVICE_ACCOUNT_JSON",
            "GOOGLE_SERVICE_ACCOUNT_JSON_BASE64",
            "GDRIVE_SERVICE_ACCOUNT_JSON_BASE64",
        )
    )
    has_folder = bool(_drive_folder_id())
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
    file_storage,
    filename: str,
    *,
    folder_id: Optional[str] = None,
    make_public: bool = True,
) -> str:
    """
    Uploads a Flask FileStorage to Google Drive and returns the created file_id (string).

    - Stores the file in GOOGLE_DRIVE_FOLDER_ID (or GDRIVE_FOLDER_ID).
    - If make_public=True, sets "anyone with the link can read".
    """
    if file_storage is None:
        raise ValueError("file_storage is None")

    if folder_id is None:
        folder_id = _drive_folder_id() or None

    if not folder_id:
        raise RuntimeError("Missing Drive folder ID. Set GOOGLE_DRIVE_FOLDER_ID or GDRIVE_FOLDER_ID.")

    # Read file bytes
    data = file_storage.read()
    try:
        file_storage.stream.seek(0)
    except Exception:
        pass

    mime_type = getattr(file_storage, "mimetype", None) or "application/octet-stream"

    service = get_drive_service()
    metadata = {"name": filename, "parents": [folder_id]}
    media = MediaIoBaseUpload(io.BytesIO(data), mimetype=mime_type, resumable=False)

    created = service.files().create(
        body=metadata,
        media_body=media,
        fields="id",
        supportsAllDrives=True,
    ).execute()

    file_id = created["id"]

    if make_public:
        service.permissions().create(
            fileId=file_id,
            body={"type": "anyone", "role": "reader"},
            fields="id",
            supportsAllDrives=True,
        ).execute()

    return file_id
