"""时间轴路由"""
from fastapi import APIRouter, Depends
from ..database import get_db
from ..config import settings
from ..dependencies import require_auth, require_role

router = APIRouter(prefix="/api", tags=["timeline"])


@router.get("/timeline")
def list_timeline():
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, event_date, title, content, photo_url, icon FROM `{settings.timeline_table}` ORDER BY event_date DESC"
            )
            rows = cursor.fetchall()
    return [
        {
            "id": r[0],
            "event_date": r[1].isoformat() if r[1] else None,
            "title": r[2],
            "content": r[3],
            "photo_url": r[4],
            "icon": r[5] or "💕",
        }
        for r in rows
    ]


@router.post("/timeline")
def create_timeline(body: dict, _=Depends(require_role("admin"))):
    event_date = str(body.get("event_date", "")).strip()
    title = str(body.get("title", "")).strip()
    content = str(body.get("content", "")).strip()
    photo_url = str(body.get("photo_url", "")).strip()
    icon = str(body.get("icon", "💕")).strip() or "💕"

    if not event_date or not title:
        return {"error": "event_date and title are required"}, 400

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO `{settings.timeline_table}` (event_date, title, content, photo_url, icon) VALUES (%s, %s, %s, %s, %s)",
                (event_date, title, content, photo_url, icon),
            )
            row_id = cursor.lastrowid
        conn.commit()
    return {"ok": True, "id": row_id}


@router.delete("/timeline")
def delete_timeline(id: int, _=Depends(require_role("admin"))):
    if id <= 0:
        return {"error": "invalid id"}, 400
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"DELETE FROM `{settings.timeline_table}` WHERE id = %s", (id,)
            )
            affected = cursor.rowcount
        conn.commit()
    if not affected:
        return {"error": "not found"}, 404
    return {"ok": True}
