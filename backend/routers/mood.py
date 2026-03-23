"""心情打卡路由"""
import datetime
from fastapi import APIRouter, Depends
from ..database import get_db
from ..config import settings
from ..dependencies import require_auth, require_role

router = APIRouter(prefix="/api", tags=["mood"])


@router.get("/mood")
def list_mood(year: int = None, month: int = None):
    today = datetime.date.today()
    if year is None:
        year = today.year
    if month is None:
        month = today.month

    start_date = f"{year:04d}-{month:02d}-01"
    if month == 12:
        end_date = f"{year + 1:04d}-01-01"
    else:
        end_date = f"{year:04d}-{month + 1:02d}-01"

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, mood_date, emoji, note, level FROM `{settings.mood_table}` WHERE mood_date >= %s AND mood_date < %s ORDER BY mood_date ASC",
                (start_date, end_date),
            )
            rows = cursor.fetchall()
    return [
        {
            "id": r[0],
            "mood_date": r[1].isoformat() if r[1] else None,
            "emoji": r[2],
            "note": r[3],
            "level": r[4],
        }
        for r in rows
    ]


@router.post("/mood")
def save_mood(body: dict, _=Depends(require_role("admin"))):
    mood_date = str(body.get("mood_date", "")).strip()
    emoji = str(body.get("emoji", "😊")).strip() or "😊"
    note = str(body.get("note", "")).strip()
    try:
        level = int(body.get("level", 3))
    except (ValueError, TypeError):
        level = 3
    level = max(1, min(5, level))

    if not mood_date:
        mood_date = datetime.date.today().isoformat()

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""INSERT INTO `{settings.mood_table}` (mood_date, emoji, note, level)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE emoji = VALUES(emoji), note = VALUES(note), level = VALUES(level)""",
                (mood_date, emoji, note, level),
            )
            row_id = cursor.lastrowid
        conn.commit()
    return {"ok": True, "id": row_id}
