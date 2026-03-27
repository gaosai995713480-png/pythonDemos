"""照片路由"""
import io
import time
import zipfile
import logging
from urllib.parse import quote, unquote

from fastapi import APIRouter, Request, Depends
from fastapi.responses import FileResponse, JSONResponse
from ..config import settings
from ..dependencies import require_gallery_access, require_role
from ..utils import is_image_filename, sanitize_upload_filename, photo_sort_key
from ..services.oss_storage import upload_to_oss, get_oss_bucket, get_oss_domain
from ..database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["photos"])


def _aligned_expires() -> int:
    """计算到下一个整点小时的剩余秒数，保证同一小时内签名 URL 完全一致，命中浏览器缓存"""
    now = int(time.time())
    next_hour = (now // 3600 + 1) * 3600
    return max(next_hour - now, 300)  # 最少保证 5 分钟有效


@router.get("/photos.json")
def list_photos(_=Depends(require_gallery_access)):
    # 彻底元数据化：优先查询数据库中的结构化对象
    bucket = get_oss_bucket()
    expires = _aligned_expires()
    try:
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, filename, oss_url, description, created_at FROM love_photos")
                rows = cursor.fetchall()
                if rows:
                    from pathlib import Path
                    
                    def _get_url(f_name, raw_url, is_thumb=False):
                        if bucket:
                            params = {'x-oss-process': 'image/resize,w_500,m_lfit'} if is_thumb else None
                            return bucket.sign_url('GET', f"photos/{f_name}", expires, slash_safe=True, params=params)
                        return raw_url

                    # 对查出来的数据行使用原生排序函数确保顺序 100% 对齐旧版相册
                    sorted_rows = sorted(rows, key=lambda r: photo_sort_key(Path(r[1])))

                    return [
                        {
                            "id": r[0],
                            "filename": r[1],
                            "url": _get_url(r[1], r[2], is_thumb=False),
                            "thumbnail_url": _get_url(r[1], r[2], is_thumb=True),
                            "description": r[3] if r[3] else "",
                            "created_at": r[4].strftime("%Y-%m-%d %H:%M:%S") if r[4] else ""
                        }
                        for r in sorted_rows
                    ]
    except Exception as e:
        logger.error(f"Database query failed: {e}")

    # 降级：如果数据库没有数据，则寻找本地遗留
    photos_dir = settings.photos_dir
    images = []
    if photos_dir.exists():
        for item in photos_dir.iterdir():
            if item.is_file() and is_image_filename(item.name):
                images.append(item)
    images.sort(key=photo_sort_key)
    # 必须仍然返回对象格式，以兼容前端新改造
    return [
        {
            "id": i,
            "filename": item.name,
            "url": f"photos/{quote(item.name)}",
            "description": "",
            "created_at": ""
        } 
        for i, item in enumerate(images)
    ]


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

    if not safe_name or not is_image_filename(safe_name):
        return JSONResponse({"error": "invalid file name"}, status_code=400)

    file_data = await request.body()
    if not file_data:
        return JSONResponse({"error": "empty file"}, status_code=400)

    # 1. 尝试直传 OSS 并入库 MySQL
    if get_oss_bucket():
        success = upload_to_oss(safe_name, file_data)
        if success:
            domain = get_oss_domain()
            oss_url = f"{domain}/photos/{safe_name}"
            try:
                with get_db() as conn:
                    with conn.cursor() as cursor:
                        cursor.execute("INSERT IGNORE INTO love_photos (filename, oss_url) VALUES (%s, %s)", (safe_name, oss_url))
                    conn.commit()
            except Exception as e:
                logger.error(f"DB Insert error: {e}")
            return {"ok": True, "saved": 1, "name": safe_name}
        return JSONResponse({"error": "failed to upload to OSS"}, status_code=500)

    # 2. 降级：走本地存储
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
    has_oss = bool(get_oss_bucket())
    if not has_oss:
        photos_dir.mkdir(parents=True, exist_ok=True)
        
    domain = get_oss_domain() if has_oss else ""

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

                file_data = archive.read(info)
                
                if has_oss:
                    if upload_to_oss(safe_name, file_data):
                        saved += 1
                        oss_url = f"{domain}/photos/{safe_name}"
                        try:
                            with get_db() as conn:
                                with conn.cursor() as cursor:
                                    cursor.execute("INSERT IGNORE INTO love_photos (filename, oss_url) VALUES (%s, %s)", (safe_name, oss_url))
                                conn.commit()
                        except Exception:
                            pass
                else:
                    target = photos_dir / safe_name
                    if target.exists():
                        skipped += 1
                        continue
                    target.write_bytes(file_data)
                    saved += 1

        return {"ok": True, "saved": saved, "skipped": skipped}
    except zipfile.BadZipFile:
        return JSONResponse({"error": "invalid zip file"}, status_code=400)


@router.delete("/photos/{file_name:path}")
def delete_photo(file_name: str, _=Depends(require_role("admin"))):
    safe_name = sanitize_upload_filename(unquote(file_name))
    if not safe_name:
        return JSONResponse({"error": "invalid photo name"}, status_code=400)

    deleted = False

    # 1. 尝试清理 OSS 及 MySQL 记录
    bucket = get_oss_bucket()
    if bucket:
        try:
            bucket.delete_object(f"photos/{safe_name}")
            with get_db() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM love_photos WHERE filename = %s", (safe_name,))
                conn.commit()
            deleted = True
        except Exception as e:
            logger.error(f"Delete from OSS/DB failed: {e}")

    # 2. 尝试清理本地硬盘遗留（不管怎样都删一下，防漏网）
    target = settings.photos_dir / safe_name
    if target.exists() and target.is_file():
        try:
            target.unlink()
            deleted = True
        except Exception:
            pass

    if deleted:
        return {"ok": True, "deleted": safe_name}
    return JSONResponse({"error": "photo not found"}, status_code=404)
