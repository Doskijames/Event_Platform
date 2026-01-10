# gdrive_storage.py (OAUTH ONLY - uses personal Drive via refresh token)
import os
import io
import json
import base64
from typing import Optional, Dict, Any, Tuple

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.errors import HttpError

SCOPES = ["https://www.googleapis.com/auth/drive"]


def _env(name: str) -> str:
    v = os.getenv(name, "")
    return v.strip() if v else ""


def _drive_folder_id() -> str:
    # Keep this exactly as your env var name
    return _env("GOOGLE_DRIVE_FOLDER_ID")


def _load_oauth_client_secret() -> Dict[str, Any]:
    """
    Loads OAuth client secret JSON from env var:
      - GOOGLE_OAUTH_CLIENT_SECRET_JSON  (raw JSON)
      - GOOGLE_OAUTH_CLIENT_SECRET_JSON_BASE64 (optional)

    The JSON is typically the Google "OAuth client" file, shaped like:
      {"installed": {...}}  or  {"web": {...}}
    """
    raw_b64 = _env("GOOGLE_OAUTH_CLIENT_SECRET_JSON_BASE64")
    raw = _env("GOOGLE_OAUTH_CLIENT_SECRET_JSON")

    if raw_b64 and not raw:
        try:
            raw = base64.b64decode(raw_b64).decode("utf-8").strip()
        except Exception as e:
            raise RuntimeError(f"Invalid GOOGLE_OAUTH_CLIENT_SECRET_JSON_BASE64: {e}") from e

    if not raw:
        raise RuntimeError(
            "Missing OAuth client secret JSON. "
            "Set GOOGLE_OAUTH_CLIENT_SECRET_JSON (raw JSON) "
            "or GOOGLE_OAUTH_CLIENT_SECRET_JSON_BASE64."
        )

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            "GOOGLE_OAUTH_CLIENT_SECRET_JSON is not valid JSON. "
            "Tip: if you're pasting into an env var, Base64 is safer. "
            f"Original error: {e}"
        ) from e

    return data


def _extract_client_id_secret(client_json: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Supports both OAuth client formats:
      {"installed": {...}} or {"web": {...}}
    Returns: (client_id, client_secret, token_uri)
    """
    block = None
    if isinstance(client_json.get("installed"), dict):
        block = client_json["installed"]
    elif isinstance(client_json.get("web"), dict):
        block = client_json["web"]
    elif isinstance(client_json, dict) and ("client_id" in client_json and "client_secret" in client_json):
        # Rare case: already flattened
        block = client_json

    if not isinstance(block, dict):
        raise RuntimeError(
            "OAuth client secret JSON is missing 'installed' or 'web' section."
        )

    client_id = (block.get("client_id") or "").strip()
    client_secret = (block.get("client_secret") or "").strip()
    token_uri = (block.get("token_uri") or "https://oauth2.googleapis.com/token").strip()

    if not client_id or not client_secret:
        raise RuntimeError("OAuth client secret JSON missing client_id/client_secret.")

    return client_id, client_secret, token_uri


def drive_enabled() -> bool:
    """
    True when OAuth + folder are configured.
    """
    has_folder = bool(_drive_folder_id())
    has_refresh = bool(_env("GOOGLE_OAUTH_REFRESH_TOKEN"))
    has_client_json = bool(_env("GOOGLE_OAUTH_CLIENT_SECRET_JSON") or _env("GOOGLE_OAUTH_CLIENT_SECRET_JSON_BASE64"))
    return has_folder and has_refresh and has_client_json


def get_drive_service():
    """
    Builds Drive API service using OAuth refresh token.
    This uses the personal Google account that generated the refresh token.
    """
    if not drive_enabled():
        raise RuntimeError(
            "Drive not configured. Need GOOGLE_DRIVE_FOLDER_ID, "
            "GOOGLE_OAUTH_CLIENT_SECRET_JSON (or _BASE64), and GOOGLE_OAUTH_REFRESH_TOKEN."
        )

    client_json = _load_oauth_client_secret()
    client_id, client_secret, token_uri = _extract_client_id_secret(client_json)
    refresh_token = _env("GOOGLE_OAUTH_REFRESH_TOKEN")

    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri=token_uri,
        client_id=client_id,
        client_secret=client_secret,
        scopes=SCOPES,
    )

    # Ensure we have a valid access token
    try:
        creds.refresh(Request())
    except Exception as e:
        raise RuntimeError(
            "Failed to refresh OAuth token. "
            "Most common causes: refresh token revoked, wrong client secret JSON, "
            "or the OAuth consent screen is still restricted (testing mode without test user). "
            f"Original error: {e}"
        ) from e

    return build("drive", "v3", credentials=creds, cache_discovery=False)


def drive_file_view_url(file_id: str) -> str:
    return f"https://drive.google.com/file/d/{file_id}/view"


def drive_file_embed_url(file_id: str) -> str:
    # best for <img src="...">
    return f"https://drive.google.com/uc?export=view&id={file_id}"


def upload_file_to_drive(
    file_storage,
    filename: str,
    *,
    folder_id: Optional[str] = None,
    make_public: bool = True,
) -> Dict[str, str]:
    """
    Uploads a Flask FileStorage to Google Drive (OAuth) and returns URLs.
    """
    if file_storage is None:
        raise ValueError("file_storage is None")

    if folder_id is None:
        folder_id = _drive_folder_id() or None

    if not folder_id:
        raise RuntimeError("Missing GOOGLE_DRIVE_FOLDER_ID.")

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
        ).execute()
    except HttpError as e:
        raise RuntimeError(f"Drive upload failed (OAuth). Folder ID wrong or no access? {e}") from e

    file_id = created["id"]

    if make_public:
        try:
            service.permissions().create(
                fileId=file_id,
                body={"type": "anyone", "role": "reader"},
                fields="id",
            ).execute()
        except HttpError as e:
            # Upload succeeded, but public permission failed (still usable for owner)
            raise RuntimeError(f"Uploaded file but failed to set public permission: {e}") from e

    return {
        "file_id": file_id,
        "view_url": drive_file_view_url(file_id),
        "download_url": drive_file_embed_url(file_id),
    }
