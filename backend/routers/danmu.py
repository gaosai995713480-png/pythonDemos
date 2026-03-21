"""弹幕路由"""
import re
from fastapi import APIRouter, Request, Depends
from ..database import get_db
from ..config import settings
from ..dependencies import require_auth

router = APIRouter(tags=["danmu"])


@router.get("/danmu")
def list_danmu(limit: int = 50):
    limit = max(1, min(limit, settings.danmu_limit))
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, content, likes FROM `{settings.danmu_table}` ORDER BY id DESC LIMIT %s",
                (limit,),
            )
            rows = cursor.fetchall()
    return [{"id": r[0], "text": r[1], "likes": r[2] or 0} for r in reversed(rows)]


@router.post("/danmu")
def send_danmu(body: dict, _=Depends(require_auth)):
    text = str(body.get("text", "")).strip()
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return {"error": "empty"}, 400
    text = text[: settings.danmu_maxlen]

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO `{settings.danmu_table}` (content) VALUES (%s)", (text,)
            )
            row_id = cursor.lastrowid
        conn.commit()
    return {"ok": True, "id": row_id, "likes": 0, "text": text}


@router.post("/danmu/like")
def like_danmu(body: dict, request: Request, _=Depends(require_auth)):
    try:
        danmu_id = int(body.get("id", 0))
    except (ValueError, TypeError):
        danmu_id = 0
    if danmu_id <= 0:
        return {"error": "invalid id"}, 400

    client_ip = (
        request.headers.get("X-Real-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.client.host
    )
    like_table = f"{settings.danmu_table}_likes"

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"INSERT IGNORE INTO `{like_table}` (danmu_id, ip) VALUES (%s, %s)",
                (danmu_id, client_ip),
            )
            if cursor.rowcount == 0:
                cursor.execute(
                    f"SELECT likes FROM `{settings.danmu_table}` WHERE id = %s",
                    (danmu_id,),
                )
                row = cursor.fetchone()
                return {
                    "ok": True,
                    "id": danmu_id,
                    "likes": row[0] if row else 0,
                    "liked": False,
                }
            cursor.execute(
                f"UPDATE `{settings.danmu_table}` SET likes = likes + 1 WHERE id = %s",
                (danmu_id,),
            )
            conn.commit()
            cursor.execute(
                f"SELECT likes FROM `{settings.danmu_table}` WHERE id = %s",
                (danmu_id,),
            )
            row = cursor.fetchone()
    return {
        "ok": True,
        "id": danmu_id,
        "likes": row[0] if row else 0,
        "liked": True,
    }
