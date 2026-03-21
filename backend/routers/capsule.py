"""时间胶囊路由"""
import datetime
from fastapi import APIRouter, Depends
from ..database import get_db
from ..config import settings
from ..dependencies import require_auth

router = APIRouter(prefix="/api", tags=["capsule"])


@router.get("/capsules")
def list_capsules():
    today = datetime.date.today()
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, content, open_date, is_opened, created_at FROM `{settings.capsule_table}` ORDER BY open_date ASC"
            )
            rows = cursor.fetchall()
    items = []
    for r in rows:
        open_date = r[2]
        is_opened = bool(r[3])
        can_open = open_date <= today if open_date else False
        items.append({
            "id": r[0],
            "content": r[1] if (is_opened or can_open) else None,
            "open_date": open_date.isoformat() if open_date else None,
            "is_opened": is_opened,
            "can_open": can_open,
            "created_at": r[4].isoformat() if r[4] else None,
        })
    return items


@router.post("/capsules")
def create_capsule(body: dict, _=Depends(require_auth)):
    content = str(body.get("content", "")).strip()
    open_date = str(body.get("open_date", "")).strip()
    if not content or not open_date:
        return {"error": "content and open_date are required"}, 400

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO `{settings.capsule_table}` (content, open_date) VALUES (%s, %s)",
                (content, open_date),
            )
            row_id = cursor.lastrowid
        conn.commit()
    return {"ok": True, "id": row_id}


@router.post("/capsules/open")
def open_capsule(body: dict, _=Depends(require_auth)):
    try:
        capsule_id = int(body.get("id", 0))
    except (ValueError, TypeError):
        capsule_id = 0
    if capsule_id <= 0:
        return {"error": "invalid id"}, 400

    today = datetime.date.today()
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, content, open_date, is_opened FROM `{settings.capsule_table}` WHERE id = %s",
                (capsule_id,),
            )
            row = cursor.fetchone()
            if not row:
                return {"error": "not found"}, 404
            open_date = row[2]
            if open_date > today:
                return {"error": "还没到开启日期哦", "can_open": False}, 403
            if not row[3]:
                cursor.execute(
                    f"UPDATE `{settings.capsule_table}` SET is_opened = 1 WHERE id = %s",
                    (capsule_id,),
                )
                conn.commit()
    return {
        "ok": True,
        "id": row[0],
        "content": row[1],
        "open_date": open_date.isoformat(),
        "is_opened": True,
    }
