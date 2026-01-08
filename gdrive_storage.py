import os
import json
import mimetypes
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
import io

SCOPES = ["https://www.googleapis.com/auth/drive"]

def _drive_service():
    raw = os.getenv("GDRIVE_SERVICE_ACCOUNT_JSON", "")
    if not raw:
        raise RuntimeError("Missing GDRIVE_SERVICE_ACCOUNT_JSON")

    creds_info = json.loads(raw)
    creds = service_account.Credentials.from_service_account_info(creds_info, scopes=SCOPES)
    return build("drive", "v3", credentials=creds)

def upload_file_to_drive(file_storage, filename: str) -> str:
    """
    Uploads a Flask uploaded file to Google Drive folder.
    Returns a public link.
    """
    folder_id = os.getenv("GDRIVE_FOLDER_ID")
    if not folder_id:
        raise RuntimeError("Missing GDRIVE_FOLDER_ID")

    service = _drive_service()

    # read bytes into memory
    file_bytes = file_storage.read()
    file_storage.stream.seek(0)

    mime_type, _ = mimetypes.guess_type(filename)
    mime_type = mime_type or "application/octet-stream"

    media = MediaIoBaseUpload(io.BytesIO(file_bytes), mimetype=mime_type, resumable=False)

    file_metadata = {
        "name": filename,
        "parents": [folder_id]
    }

    created = service.files().create(
        body=file_metadata,
        media_body=media,
        fields="id"
    ).execute()

    file_id = created["id"]

    # Make it public so anyone can view
    service.permissions().create(
        fileId=file_id,
        body={"type": "anyone", "role": "reader"}
    ).execute()

    # Public direct-view link
    return f"https://drive.google.com/uc?id={file_id}"
