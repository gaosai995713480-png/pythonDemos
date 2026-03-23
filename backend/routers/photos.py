"""照片路由"""
import io
import zipfile
from urllib.parse import quote, unquote

from fastapi import APIRouter, Request, Depends
from fastapi.responses import FileResponse, JSONResponse
from ..config import settings
from ..dependencies import require_gallery_access, require_role
from ..utils import is_image_filename, sanitize_upload_filename, photo_sort_key

router = APIRouter(tags=["photos"])


@router.get("/photos.json")
def list_photos(_=Depends(require_gallery_access)):
    photos_dir = settings.photos_dir
    images = []
    if photos_dir.exists():
        for item in photos_dir.iterdir():
            if item.is_file() and is_image_filename(item.name):
                images.append(item)
    images.sort(key=photo_sort_key)
    return [f"photos/{quote(item.name)}" for item in images]


@router.get("/photos/{file_name:path}")
def get_photo(file_name: str, _=Depends(require_gallery_access)):
    safe_name = sanitize_upload_filename(unquote(file_name))
    if not safe_name or not is_image_filename(safe_name):
        return JSONResponse({"error": "invalid photo name"}, status_code=400)

    target = settings.photos_dir / safe_name
    if not target.exists() or not target.is_file():
        return JSONResponse({"error": "photo not found"}, status_code=404)

    return FileResponse(target)


@router.post("/photos/upload-file")
async def upload_photo(request: Request, _=Depends(require_role("admin"))):
    file_name = request.headers.get("X-File-Name", "").strip()
    file_name = unquote(file_name)
    safe_name = sanitize_upload_filename(file_name)

    if not safe_name:
        return JSONResponse({"error": "missing file name"}, status_code=400)
    if not is_image_filename(safe_name):
        return JSONResponse({"error": "only image files are allowed"}, status_code=400)

    file_data = await request.body()
    if not file_data:
        return JSONResponse({"error": "empty file"}, status_code=400)

    photos_dir = settings.photos_dir
    photos_dir.mkdir(parents=True, exist_ok=True)
    target = photos_dir / safe_name

    if target.exists():
        return {"ok": True, "saved": 0, "name": safe_name, "skipped": True}

    target.write_bytes(file_data)
    return {"ok": True, "saved": 1, "name": safe_name}


@router.post("/photos/import")
async def import_photos(request: Request, _=Depends(require_role("admin"))):
    archive_data = await request.body()
    if not archive_data:
        return JSONResponse({"error": "empty upload"}, status_code=400)

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
        return JSONResponse({"error": "invalid zip file"}, status_code=400)

    return {"ok": True, "saved": saved, "skipped": skipped}
