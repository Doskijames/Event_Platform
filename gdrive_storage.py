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

    Supported (choose ONE):
      - GOOGLE_SERVICE_ACCOUNT_JSON: raw JSON string
      - GOOGLE_SERVICE_ACCOUNT_JSON_BASE64: base64 JSON string

    Also supports legacy/alternate names:
      - GDRIVE_SERVICE_ACCOUNT_JSON
      - GDRIVE_SERVICE_ACCOUNT_JSON_BASE64

    Notes:
      - We do NOT try to "fix" raw JSON beyond \\n -> \n
      - Base64 is recommended on Render to avoid newline/control character issues.
    """
    raw_b64 = _env_first(
        "GOOGLE_SERVICE_ACCOUNT_JSON_BASE64",
        "GDRIVE_SERVICE_ACCOUNT_JSON_BASE64",
        # optional aliases some people use:
        "GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON_BASE64",
        "GOOGLE_SERVICE_ACCOUNT_B64",
    )
    raw = _env_first(
        "GOOGLE_SERVICE_ACCOUNT_JSON",
        "GDRIVE_SERVICE_ACCOUNT_JSON",
        # optional alias some people use:
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
            "Set GOOGLE_SERVICE_ACCOUNT_JSON / GOOGLE_SERVICE_ACCOUNT_JSON_BASE64 "
            "or GDRIVE_SERVICE_ACCOUNT_JSON / GDRIVE_SERVICE_ACCOUNT_JSON_BASE64."
        )

    # Common ENV escaping: private_key sometimes has literal '\n'
    raw_fixed = raw.replace("\\n", "\n")

    try:
        info = json.loads(raw_fixed)
    except Exception as e:
        raise RuntimeError(f"Service account JSON is not valid JSON: {e}")

    # Ensure private_key newlines are correct even if JSON parsed with \\n literals
    pk = info.get("private_key")
    if isinstance(pk, str):
        info["private_key"] = pk.replace("\\n", "\n")

    return info


def drive_enabled() -> bool:
    """True when Drive integration is configured."""
    has_creds = bool(
        _env_first(
            "GOOGLE_SERVICE_ACCOUNT_JSON",
            "GDRIVE_SERVICE_ACCOUNT_JSON",
            "GOOGLE_SERVICE_ACCOUNT_JSON_BASE64",
            "GDRIVE_SERVICE_ACCOUNT_JSON_BASE64",
            "GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON",
            "GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON_BASE64",
        )
    )
    has_folder = bool(_drive_folder_id())
    return has_creds and has_folder


def get_drive_service():
    """Builds a Google Drive API service using service account credentials."""
    info = _load_service_account_info()
    creds = service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def drive_file_view_url(file_id: str) -> str:
    """Human-friendly view page."""
    return f"https://drive.google.com/file/d/{file_id}/view"


def drive_file_embed_url(file_id: str) -> str:
    """
    Direct-ish link good for <img src="...">.
    (Drive can still apply some restrictions depending on settings, but this is the usual best.)
    """
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

    Returns a dict (so your routes can meta.get(...)):
      {
        "file_id": "...",
        "view_url": "...",
        "download_url": "..."   # embed-friendly URL
      }

    Notes:
    - folder_id defaults to GOOGLE_DRIVE_FOLDER_ID (or GDRIVE_FOLDER_ID)
    - If make_public=True, sets "anyone with the link can read"
    - If you get 404 "File not found: <folderId>", the folder id is wrong OR
      the service account lacks permission to that folder (share it with client_email).
    """
    if file_storage is None:
        raise ValueError("file_storage is None")

    if folder_id is None:
        folder_id = _drive_folder_id() or None

    if not folder_id:
        raise RuntimeError("Missing Drive folder ID. Set GOOGLE_DRIVE_FOLDER_ID or GDRIVE_FOLDER_ID.")

    # Read file bytes (and reset stream so Flask/Werkzeug won't break later)
    data = file_storage.read()
    try:
        file_storage.stream.seek(0)
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
        # Keep message helpful for the most common cause: wrong folder id / no permission
        raise RuntimeError(f"Drive upload failed (create). Check folder_id permission. {e}") from e

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
            # Upload succeeded, but permission setting failed (still return links)
            # You can decide if you want to raise instead.
            # For now: raise so you notice misconfig.
            raise RuntimeError(f"Drive upload succeeded but permission set failed. {e}") from e

    return {
        "file_id": file_id,
        "view_url": drive_file_view_url(file_id),
        "download_url": drive_file_embed_url(file_id),
    }
