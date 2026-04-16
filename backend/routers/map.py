"""恋爱地图路由"""
import time
from urllib.parse import unquote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from ..database import get_db
from ..config import settings
from ..dependencies import require_role
from ..utils import sanitize_upload_filename, is_image_filename
from ..services.oss_storage import upload_to_oss, get_oss_domain, delete_from_oss

router = APIRouter(prefix="/api", tags=["map"])


def _error(message: str, status_code: int) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code)


def _normalize_photo_urls(raw_photos) -> list[str]:
    if not isinstance(raw_photos, list):
        return []
    photos = []
    for item in raw_photos:
        url = str(item or "").strip()
        if url:
            photos.append(url)
    return photos


def _marker_exists(cursor, row_id: int) -> bool:
    cursor.execute(
        f"SELECT 1 FROM `{settings.map_table}` WHERE id = %s",
        (row_id,),
    )
    return cursor.fetchone() is not None


@router.post("/map/upload")
async def upload_map_photo(request: Request, _=Depends(require_role("admin"))):
    """上传足迹照片到 OSS map/ 前缀下"""
    file_name = request.headers.get("X-File-Name", "").strip()
    file_name = unquote(file_name)
    safe_name = sanitize_upload_filename(file_name)

    if not safe_name or not is_image_filename(safe_name):
        return JSONResponse({"error": "invalid file name"}, status_code=400)

    file_data = await request.body()
    if not file_data:
        return JSONResponse({"error": "empty file"}, status_code=400)

    # 加时间戳防重名
    ts = int(time.time() * 1000)
    dot_idx = safe_name.rfind('.')
    if dot_idx > 0:
        safe_name = f"{safe_name[:dot_idx]}_{ts}{safe_name[dot_idx:]}"
    else:
        safe_name = f"{safe_name}_{ts}"

    success = upload_to_oss(safe_name, file_data, prefix="map")
    if success:
        domain = get_oss_domain()
        url = f"{domain}/map/{safe_name}"
        return {"ok": True, "url": url, "name": safe_name}
    return _error("upload failed", 500)


@router.post("/map/upload/cleanup")
def cleanup_map_uploads(body: dict, _=Depends(require_role("admin"))):
    names = body.get("names", [])
    if not isinstance(names, list):
        return _error("invalid names", 400)

    deleted = 0
    for item in names:
        safe_name = sanitize_upload_filename(str(item or "").strip())
        if not safe_name or not is_image_filename(safe_name):
            continue
        if delete_from_oss(f"map/{safe_name}"):
            deleted += 1
    return {"ok": True, "deleted": deleted}


@router.get("/map")
def list_markers():
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, title, note, photo_url, lat, lng, visit_date, created_at FROM `{settings.map_table}` ORDER BY visit_date DESC"
            )
            rows = cursor.fetchall()

            # 查所有照片
            cursor.execute(
                f"SELECT marker_id, photo_url FROM `{settings.map_photos_table}` ORDER BY sort_order, id"
            )
            photo_rows = cursor.fetchall()

    # 按 marker_id 分组
    photos_map = {}
    for pr in photo_rows:
        photos_map.setdefault(pr[0], []).append(pr[1])

    return [
        {
            "id": r[0], "title": r[1], "note": r[2], "photo_url": r[3],
            "lat": r[4], "lng": r[5],
            "visit_date": r[6].isoformat() if r[6] else None,
            "created_at": r[7].isoformat() if r[7] else None,
            "photos": photos_map.get(r[0], []),
        }
        for r in rows
    ]


@router.post("/map")
def create_marker(body: dict, _=Depends(require_role("admin"))):
    title = str(body.get("title", "")).strip()
    note = str(body.get("note", "")).strip()
    visit_date = str(body.get("visit_date", "")).strip()
    photos = _normalize_photo_urls(body.get("photos", []))
    try:
        lat = float(body.get("lat", 0))
        lng = float(body.get("lng", 0))
    except (ValueError, TypeError):
        return _error("invalid coordinates", 400)

    if not title or lat == 0 or lng == 0:
        return _error("title, lat, lng are required", 400)

    # 第一张作为封面
    cover = photos[0] if photos else ""

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO `{settings.map_table}` (title, note, photo_url, lat, lng, visit_date) VALUES (%s, %s, %s, %s, %s, %s)",
                (title, note, cover, lat, lng, visit_date or None),
            )
            row_id = cursor.lastrowid
            # 插入照片
            for i, url in enumerate(photos):
                cursor.execute(
                    f"INSERT INTO `{settings.map_photos_table}` (marker_id, photo_url, sort_order) VALUES (%s, %s, %s)",
                    (row_id, url, i),
                )
        conn.commit()
    return {"ok": True, "id": row_id}


@router.put("/map")
def update_marker(body: dict, _=Depends(require_role("admin"))):
    try:
        row_id = int(body.get("id", 0))
    except (ValueError, TypeError):
        row_id = 0
    if row_id <= 0:
        return _error("invalid id", 400)

    title = str(body.get("title", "")).strip()
    note = str(body.get("note", "")).strip()
    visit_date = str(body.get("visit_date", "")).strip()
    photos = _normalize_photo_urls(body.get("photos", []))
    try:
        lat = float(body.get("lat", 0))
        lng = float(body.get("lng", 0))
    except (ValueError, TypeError):
        return _error("invalid coordinates", 400)

    if not title:
        return _error("title is required", 400)

    cover = photos[0] if photos else ""

    with get_db() as conn:
        with conn.cursor() as cursor:
            if not _marker_exists(cursor, row_id):
                return _error("not found", 404)
            cursor.execute(
                f"UPDATE `{settings.map_table}` SET title=%s, note=%s, photo_url=%s, lat=%s, lng=%s, visit_date=%s WHERE id=%s",
                (title, note, cover, lat, lng, visit_date or None, row_id),
            )
            # 先删旧照片再插新照片
            cursor.execute(
                f"DELETE FROM `{settings.map_photos_table}` WHERE marker_id = %s", (row_id,)
            )
            for i, url in enumerate(photos):
                cursor.execute(
                    f"INSERT INTO `{settings.map_photos_table}` (marker_id, photo_url, sort_order) VALUES (%s, %s, %s)",
                    (row_id, url, i),
                )
        conn.commit()
    return {"ok": True}


@router.delete("/map")
def delete_marker(id: int, _=Depends(require_role("admin"))):
    if id <= 0:
        return _error("invalid id", 400)
    with get_db() as conn:
        with conn.cursor() as cursor:
            if not _marker_exists(cursor, id):
                return _error("not found", 404)
            # 先删照片再删主记录
            cursor.execute(
                f"DELETE FROM `{settings.map_photos_table}` WHERE marker_id = %s", (id,)
            )
            cursor.execute(
                f"DELETE FROM `{settings.map_table}` WHERE id = %s", (id,)
            )
        conn.commit()
    return {"ok": True}
