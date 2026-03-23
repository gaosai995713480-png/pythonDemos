"""恋爱地图路由"""
from fastapi import APIRouter, Depends
from ..database import get_db
from ..config import settings
from ..dependencies import require_auth, require_role

router = APIRouter(prefix="/api", tags=["map"])


@router.get("/map")
def list_markers():
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, title, note, photo_url, lat, lng, visit_date, created_at FROM `{settings.map_table}` ORDER BY visit_date DESC"
            )
            rows = cursor.fetchall()
    return [
        {
            "id": r[0], "title": r[1], "note": r[2], "photo_url": r[3],
            "lat": r[4], "lng": r[5],
            "visit_date": r[6].isoformat() if r[6] else None,
            "created_at": r[7].isoformat() if r[7] else None,
        }
        for r in rows
    ]


@router.post("/map")
def create_marker(body: dict, _=Depends(require_role("admin"))):
    title = str(body.get("title", "")).strip()
    note = str(body.get("note", "")).strip()
    photo_url = str(body.get("photo_url", "")).strip()
    visit_date = str(body.get("visit_date", "")).strip()
    try:
        lat = float(body.get("lat", 0))
        lng = float(body.get("lng", 0))
    except (ValueError, TypeError):
        return {"error": "invalid coordinates"}, 400

    if not title or lat == 0 or lng == 0:
        return {"error": "title, lat, lng are required"}, 400

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO `{settings.map_table}` (title, note, photo_url, lat, lng, visit_date) VALUES (%s, %s, %s, %s, %s, %s)",
                (title, note, photo_url, lat, lng, visit_date or None),
            )
            row_id = cursor.lastrowid
        conn.commit()
    return {"ok": True, "id": row_id}


@router.put("/map")
def update_marker(body: dict, _=Depends(require_role("admin"))):
    try:
        row_id = int(body.get("id", 0))
    except (ValueError, TypeError):
        row_id = 0
    if row_id <= 0:
        return {"error": "invalid id"}, 400

    title = str(body.get("title", "")).strip()
    note = str(body.get("note", "")).strip()
    photo_url = str(body.get("photo_url", "")).strip()
    visit_date = str(body.get("visit_date", "")).strip()
    try:
        lat = float(body.get("lat", 0))
        lng = float(body.get("lng", 0))
    except (ValueError, TypeError):
        return {"error": "invalid coordinates"}, 400

    if not title:
        return {"error": "title is required"}, 400

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"UPDATE `{settings.map_table}` SET title=%s, note=%s, photo_url=%s, lat=%s, lng=%s, visit_date=%s WHERE id=%s",
                (title, note, photo_url, lat, lng, visit_date or None, row_id),
            )
            affected = cursor.rowcount
        conn.commit()
    if not affected:
        return {"error": "not found"}, 404
    return {"ok": True}


@router.delete("/map")
def delete_marker(id: int, _=Depends(require_role("admin"))):
    if id <= 0:
        return {"error": "invalid id"}, 400
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"DELETE FROM `{settings.map_table}` WHERE id = %s", (id,)
            )
            affected = cursor.rowcount
        conn.commit()
    if not affected:
        return {"error": "not found"}, 404
    return {"ok": True}
