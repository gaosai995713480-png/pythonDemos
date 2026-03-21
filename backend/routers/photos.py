"""照片路由"""
import io
import re
import zipfile
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Request, Depends
from ..config import settings
from ..dependencies import require_auth

router = APIRouter(tags=["photos"])

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"}
WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def is_image_filename(name: str) -> bool:
    return Path(name).suffix.lower() in IMAGE_EXTENSIONS


def sanitize_upload_filename(raw_name: str) -> str:
    name = (raw_name or "").strip().replace("\x00", "")
    if not name:
        return ""
    name = name.replace("\\", "/").split("/")[-1].strip()
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).rstrip(" .")
    if not name:
        return ""
    if Path(name).stem.lower() in WINDOWS_RESERVED_NAMES:
        name = f"_{name}"
    return name


def photo_sort_key(path: Path) -> tuple:
    stem = path.stem
    parts = stem.split("_")
    if len(parts) >= 3 and parts[2].isdigit():
        return (0, int(parts[2]), path.name.lower())
    return (1, 10**9, path.name.lower())


@router.get("/photos.json")
def list_photos():
    photos_dir = settings.photos_dir
    images = []
    if photos_dir.exists():
        for item in photos_dir.iterdir():
            if item.is_file() and is_image_filename(item.name):
                images.append(item)
    images.sort(key=photo_sort_key)
    return [f"photos/{quote(item.name)}" for item in images]


@router.post("/photos/upload-file")
async def upload_photo(request: Request, _=Depends(require_auth)):
    file_name = request.headers.get("X-File-Name", "").strip()
    from urllib.parse import unquote
    file_name = unquote(file_name)
    safe_name = sanitize_upload_filename(file_name)

    if not safe_name:
        return {"error": "missing file name"}, 400
    if not is_image_filename(safe_name):
        return {"error": "only image files are allowed"}, 400

    file_data = await request.body()
    if not file_data:
        return {"error": "empty file"}, 400

    photos_dir = settings.photos_dir
    photos_dir.mkdir(parents=True, exist_ok=True)
    target = photos_dir / safe_name

    if target.exists():
        return {"ok": True, "saved": 0, "name": safe_name, "skipped": True}

    target.write_bytes(file_data)
    return {"ok": True, "saved": 1, "name": safe_name}


@router.post("/photos/import")
async def import_photos(request: Request, _=Depends(require_auth)):
    archive_data = await request.body()
    if not archive_data:
        return {"error": "empty upload"}, 400

    photos_dir = settings.photos_dir
    photos_dir.mkdir(parents=True, exist_ok=True)

    try:
        saved = 0
        skipped = 0
        with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                safe_name = sanitize_upload_filename(info.filename)
                if not safe_name or not is_image_filename(safe_name):
                    continue
                target = photos_dir / safe_name
                if target.exists():
                    skipped += 1
                    continue
                target.write_bytes(archive.read(info))
                saved += 1
    except zipfile.BadZipFile:
        return {"error": "invalid zip file"}, 400

    return {"ok": True, "saved": saved, "skipped": skipped}
