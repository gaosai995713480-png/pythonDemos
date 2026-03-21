"""星空许愿路由"""
from fastapi import APIRouter, Depends
from ..database import get_db
from ..config import settings
from ..dependencies import require_auth

router = APIRouter(prefix="/api", tags=["wish"])


@router.get("/wishes")
def list_wishes():
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, content, x, y, color, created_at FROM `{settings.wish_table}` ORDER BY created_at DESC"
            )
            rows = cursor.fetchall()
    return [
        {
            "id": r[0], "content": r[1], "x": r[2], "y": r[3],
            "color": r[4], "created_at": r[5].isoformat() if r[5] else None,
        }
        for r in rows
    ]


@router.post("/wishes")
def create_wish(body: dict, _=Depends(require_auth)):
    content = str(body.get("content", "")).strip()
    x = float(body.get("x", 0.5))
    y = float(body.get("y", 0.5))
    color = str(body.get("color", "#ffd700")).strip()
    if not content:
        return {"error": "content required"}, 400

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO `{settings.wish_table}` (content, x, y, color) VALUES (%s, %s, %s, %s)",
                (content, x, y, color),
            )
            row_id = cursor.lastrowid
        conn.commit()
    return {"ok": True, "id": row_id}
