"""做菜食谱与情侣做饭清单 API。"""
from __future__ import annotations

import json
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ..database import get_db
from ..dependencies import get_current_user, require_auth

router = APIRouter(prefix="/api", tags=["recipes"])


def _current_username(request: Request) -> str:
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="unauthorized")
    return user.username


def _json_array(value: Any) -> list:
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _date_str(value: Any) -> str | None:
    if not value:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _clamp_page_size(page_size: int) -> int:
    return max(1, min(page_size, 100))


def _ensure_recipe_exists(cursor, recipe_id: int) -> None:
    cursor.execute(
        """
        SELECT id FROM `love_recipes`
        WHERE id = %s AND is_enabled = 1 AND is_archived = 0
        """,
        (recipe_id,),
    )
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="菜谱不存在")


def _ensure_menu_owner(cursor, menu_id: int, username: str) -> None:
    cursor.execute(
        """
        SELECT id FROM `love_cooking_menus`
        WHERE id = %s AND created_by = %s
        """,
        (menu_id, username),
    )
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="菜单不存在")


@router.get("/recipes")
def list_recipes(
    request: Request,
    keyword: str = "",
    category: str = "",
    tag: str = "",
    difficulty: str = "",
    max_cook_time: int | None = None,
    only_favorite: bool = False,
    only_want_to_cook: bool = False,
    only_cooked: bool = False,
    page: int = 1,
    page_size: int = 20,
    _=Depends(require_auth),
):
    username = _current_username(request)
    page = max(page, 1)
    page_size = _clamp_page_size(page_size)
    where = ["r.is_enabled = 1", "r.is_archived = 0"]
    params: list[Any] = [username]

    if keyword.strip():
        where.append("(r.title LIKE %s OR r.description LIKE %s OR r.raw_markdown LIKE %s)")
        like = f"%{keyword.strip()}%"
        params.extend([like, like, like])
    if category.strip():
        where.append("r.category = %s")
        params.append(category.strip())
    if tag.strip():
        where.append("JSON_CONTAINS(r.tags_json, JSON_QUOTE(%s))")
        params.append(tag.strip())
    if difficulty.strip():
        where.append("r.difficulty = %s")
        params.append(difficulty.strip())
    if max_cook_time is not None and max_cook_time > 0:
        where.append("(r.cook_time_minutes IS NULL OR r.cook_time_minutes <= %s)")
        params.append(max_cook_time)
    if only_favorite:
        where.append("COALESCE(s.is_favorite, 0) = 1")
    if only_want_to_cook:
        where.append("COALESCE(s.want_to_cook, 0) = 1")
    if only_cooked:
        where.append("COALESCE(s.cooked_count, 0) > 0")

    where_sql = " AND ".join(where)
    count_params = params[1:]
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT COUNT(*) FROM `love_recipes` r
                LEFT JOIN `love_recipe_user_states` s
                    ON s.recipe_id = r.id AND s.username = %s
                WHERE {where_sql}
                """,
                params,
            )
            total = int(cursor.fetchone()[0])

            offset = (page - 1) * page_size
            cursor.execute(
                f"""
                SELECT r.id, r.title, r.category, r.description, r.difficulty,
                       r.cook_time_minutes, r.tags_json,
                       COALESCE(s.is_favorite, 0), COALESCE(s.want_to_cook, 0),
                       COALESCE(s.cooked_count, 0), s.last_cooked_at, s.rating
                FROM `love_recipes` r
                LEFT JOIN `love_recipe_user_states` s
                    ON s.recipe_id = r.id AND s.username = %s
                WHERE {where_sql}
                ORDER BY r.category, r.title
                LIMIT %s OFFSET %s
                """,
                params + [page_size, offset],
            )
            rows = cursor.fetchall()

    return {
        "items": [
            {
                "id": r[0],
                "title": r[1],
                "category": r[2] or "",
                "description": r[3] or "",
                "difficulty": r[4] or "unknown",
                "cook_time_minutes": r[5],
                "tags": _json_array(r[6]),
                "is_favorite": bool(r[7]),
                "want_to_cook": bool(r[8]),
                "cooked_count": int(r[9] or 0),
                "last_cooked_at": _date_str(r[10]),
                "rating": r[11],
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/recipes/categories")
def list_recipe_categories(_=Depends(require_auth)):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT DISTINCT category, COUNT(*) FROM `love_recipes`
                WHERE is_enabled = 1 AND is_archived = 0 AND category <> ''
                GROUP BY category
                ORDER BY category
                """
            )
            rows = cursor.fetchall()
    return {"items": [{"category": r[0], "count": int(r[1])} for r in rows]}


@router.get("/recipes/random")
def random_recipe(
    request: Request,
    category: str = "",
    difficulty: str = "",
    max_cook_time: int | None = None,
    _=Depends(require_auth),
):
    username = _current_username(request)
    where = ["r.is_enabled = 1", "r.is_archived = 0"]
    params: list[Any] = [username]
    if category.strip():
        where.append("r.category = %s")
        params.append(category.strip())
    if difficulty.strip():
        where.append("r.difficulty = %s")
        params.append(difficulty.strip())
    if max_cook_time is not None and max_cook_time > 0:
        where.append("(r.cook_time_minutes IS NULL OR r.cook_time_minutes <= %s)")
        params.append(max_cook_time)
    where_sql = " AND ".join(where)
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT r.id, r.title, r.category, r.description, r.difficulty,
                       r.cook_time_minutes, r.tags_json,
                       COALESCE(s.is_favorite, 0), COALESCE(s.want_to_cook, 0),
                       COALESCE(s.cooked_count, 0), s.last_cooked_at, s.rating
                FROM `love_recipes` r
                LEFT JOIN `love_recipe_user_states` s
                    ON s.recipe_id = r.id AND s.username = %s
                WHERE {where_sql}
                ORDER BY RAND()
                LIMIT 1
                """,
                params,
            )
            row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="没有可推荐的菜谱")
    return {
        "id": row[0],
        "title": row[1],
        "category": row[2] or "",
        "description": row[3] or "",
        "difficulty": row[4] or "unknown",
        "cook_time_minutes": row[5],
        "tags": _json_array(row[6]),
        "is_favorite": bool(row[7]),
        "want_to_cook": bool(row[8]),
        "cooked_count": int(row[9] or 0),
        "last_cooked_at": _date_str(row[10]),
        "rating": row[11],
    }


@router.get("/recipes/{recipe_id}")
def recipe_detail(recipe_id: int, request: Request, _=Depends(require_auth)):
    username = _current_username(request)
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, source, source_repo, source_commit, source_path, title,
                       category, description, raw_markdown, ingredients_json,
                       steps_json, tips, difficulty, cook_time_minutes, servings,
                       tags_json, COALESCE(s.is_favorite, 0), COALESCE(s.want_to_cook, 0),
                       COALESCE(s.cooked_count, 0), s.last_cooked_at, s.rating, s.note
                FROM `love_recipes` r
                LEFT JOIN `love_recipe_user_states` s
                    ON s.recipe_id = r.id AND s.username = %s
                WHERE r.id = %s AND r.is_enabled = 1 AND r.is_archived = 0
                """,
                (username, recipe_id),
            )
            row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="菜谱不存在")
    return {
        "id": row[0],
        "source": row[1],
        "source_repo": row[2] or "",
        "source_commit": row[3] or "",
        "source_path": row[4] or "",
        "title": row[5],
        "category": row[6] or "",
        "description": row[7] or "",
        "raw_markdown": row[8] or "",
        "ingredients": _json_array(row[9]),
        "steps": _json_array(row[10]),
        "tips": row[11] or "",
        "difficulty": row[12] or "unknown",
        "cook_time_minutes": row[13],
        "servings": row[14],
        "tags": _json_array(row[15]),
        "user_state": {
            "is_favorite": bool(row[16]),
            "want_to_cook": bool(row[17]),
            "cooked_count": int(row[18] or 0),
            "last_cooked_at": _date_str(row[19]),
            "rating": row[20],
            "note": row[21] or "",
        },
    }


@router.post("/recipes/{recipe_id}/state")
def update_recipe_state(
    recipe_id: int, body: dict, request: Request, _=Depends(require_auth)
):
    username = _current_username(request)
    rating = body.get("rating")
    if rating is not None:
        rating = int(rating)
        if rating < 1 or rating > 5:
            raise HTTPException(status_code=400, detail="评分必须在1-5之间")
    note = str(body.get("note", ""))[:500]
    with get_db() as conn:
        with conn.cursor() as cursor:
            _ensure_recipe_exists(cursor, recipe_id)
            cursor.execute(
                """
                INSERT INTO `love_recipe_user_states`
                    (recipe_id, username, is_favorite, want_to_cook, rating, note)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    is_favorite = VALUES(is_favorite),
                    want_to_cook = VALUES(want_to_cook),
                    rating = VALUES(rating),
                    note = VALUES(note)
                """,
                (
                    recipe_id,
                    username,
                    1 if body.get("is_favorite") else 0,
                    1 if body.get("want_to_cook") else 0,
                    rating,
                    note,
                ),
            )
        conn.commit()
    return {"ok": True}


@router.post("/recipes/{recipe_id}/records")
def add_cooking_record(
    recipe_id: int, body: dict, request: Request, _=Depends(require_auth)
):
    username = _current_username(request)
    cooked_date = str(body.get("cooked_date", "")).strip() or date.today().isoformat()
    rating = body.get("rating")
    if rating is not None:
        rating = int(rating)
        if rating < 1 or rating > 5:
            raise HTTPException(status_code=400, detail="评分必须在1-5之间")
    mood = str(body.get("mood", ""))[:30]
    photo_url = str(body.get("photo_url", ""))[:500]
    note = str(body.get("note", ""))
    next_time_improvement = str(body.get("next_time_improvement", ""))
    with get_db() as conn:
        with conn.cursor() as cursor:
            _ensure_recipe_exists(cursor, recipe_id)
            cursor.execute(
                """
                INSERT INTO `love_cooking_records`
                    (recipe_id, username, cooked_date, rating, mood, photo_url, note, next_time_improvement)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    recipe_id,
                    username,
                    cooked_date,
                    rating,
                    mood,
                    photo_url,
                    note,
                    next_time_improvement,
                ),
            )
            record_id = cursor.lastrowid
            cursor.execute(
                """
                INSERT INTO `love_recipe_user_states`
                    (recipe_id, username, cooked_count, last_cooked_at, rating, want_to_cook)
                VALUES (%s, %s, 1, %s, %s, 0)
                ON DUPLICATE KEY UPDATE
                    cooked_count = cooked_count + 1,
                    last_cooked_at = VALUES(last_cooked_at),
                    rating = VALUES(rating),
                    want_to_cook = 0
                """,
                (recipe_id, username, cooked_date, rating),
            )
        conn.commit()
    return {"ok": True, "id": record_id}


@router.get("/recipes/{recipe_id}/records")
def recipe_records(recipe_id: int, request: Request, _=Depends(require_auth)):
    username = _current_username(request)
    return _list_records(username=username, recipe_id=recipe_id)


@router.get("/cooking/records")
def cooking_records(request: Request, _=Depends(require_auth)):
    username = _current_username(request)
    return _list_records(username=username)


def _list_records(username: str, recipe_id: int | None = None):
    where = ["cr.username = %s"]
    params: list[Any] = [username]
    if recipe_id is not None:
        where.append("cr.recipe_id = %s")
        params.append(recipe_id)
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT cr.id, cr.recipe_id, r.title, cr.cooked_date, cr.rating,
                       cr.mood, cr.photo_url, cr.note, cr.next_time_improvement
                FROM `love_cooking_records` cr
                JOIN `love_recipes` r ON r.id = cr.recipe_id
                WHERE {" AND ".join(where)}
                ORDER BY cr.cooked_date DESC, cr.id DESC
                LIMIT 100
                """,
                params,
            )
            rows = cursor.fetchall()
    return {
        "items": [
            {
                "id": r[0],
                "recipe_id": r[1],
                "title": r[2],
                "cooked_date": _date_str(r[3]),
                "rating": r[4],
                "mood": r[5] or "",
                "photo_url": r[6] or "",
                "note": r[7] or "",
                "next_time_improvement": r[8] or "",
            }
            for r in rows
        ]
    }


@router.get("/cooking/menus")
def list_menus(request: Request, _=Depends(require_auth)):
    username = _current_username(request)
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, menu_date, description, status
                FROM `love_cooking_menus`
                WHERE created_by = %s
                ORDER BY COALESCE(menu_date, DATE(created_at)) DESC, id DESC
                """,
                (username,),
            )
            rows = cursor.fetchall()
            menu_ids = [r[0] for r in rows]
            items_by_menu: dict[int, list[dict[str, Any]]] = {menu_id: [] for menu_id in menu_ids}
            if menu_ids:
                placeholders = ",".join(["%s"] * len(menu_ids))
                cursor.execute(
                    f"""
                    SELECT mi.id, mi.menu_id, mi.recipe_id, r.title, mi.sort_order, mi.note
                    FROM `love_cooking_menu_items` mi
                    JOIN `love_recipes` r ON r.id = mi.recipe_id
                    WHERE mi.menu_id IN ({placeholders})
                      AND r.is_enabled = 1
                      AND r.is_archived = 0
                    ORDER BY mi.menu_id, mi.sort_order, mi.id
                    """,
                    menu_ids,
                )
                for item in cursor.fetchall():
                    items_by_menu.setdefault(item[1], []).append(
                        {
                            "id": item[0],
                            "recipe_id": item[2],
                            "title": item[3],
                            "sort_order": int(item[4] or 0),
                            "note": item[5] or "",
                        }
                    )
    return {
        "items": [
            {
                "id": r[0],
                "title": r[1],
                "menu_date": _date_str(r[2]),
                "description": r[3] or "",
                "status": r[4],
                "items": items_by_menu.get(r[0], []),
            }
            for r in rows
        ]
    }


@router.post("/cooking/menus")
def create_menu(body: dict, request: Request, _=Depends(require_auth)):
    username = _current_username(request)
    title = str(body.get("title", "")).strip()[:120]
    if not title:
        raise HTTPException(status_code=400, detail="菜单标题不能为空")
    menu_date = str(body.get("menu_date", "")).strip() or None
    description = str(body.get("description", "")).strip()[:500]
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO `love_cooking_menus`
                    (title, menu_date, description, status, created_by)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (title, menu_date, description, "planned", username),
            )
            row_id = cursor.lastrowid
        conn.commit()
    return {"ok": True, "id": row_id}


@router.post("/cooking/menus/{menu_id}/items")
def add_menu_item(
    menu_id: int, body: dict, request: Request, _=Depends(require_auth)
):
    username = _current_username(request)
    recipe_id = int(body.get("recipe_id") or 0)
    if recipe_id <= 0:
        raise HTTPException(status_code=400, detail="recipe_id 无效")
    note = str(body.get("note", "")).strip()[:300]
    with get_db() as conn:
        with conn.cursor() as cursor:
            _ensure_menu_owner(cursor, menu_id, username)
            _ensure_recipe_exists(cursor, recipe_id)
            cursor.execute(
                """
                INSERT INTO `love_cooking_menu_items`
                    (menu_id, recipe_id, sort_order, note)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE note = VALUES(note)
                """,
                (menu_id, recipe_id, int(body.get("sort_order") or 0), note),
            )
            row_id = cursor.lastrowid
        conn.commit()
    return {"ok": True, "id": row_id}


@router.post("/cooking/menus/{menu_id}/complete")
def complete_menu(menu_id: int, request: Request, _=Depends(require_auth)):
    username = _current_username(request)
    with get_db() as conn:
        with conn.cursor() as cursor:
            _ensure_menu_owner(cursor, menu_id, username)
            cursor.execute(
                """
                UPDATE `love_cooking_menus`
                SET status = 'done'
                WHERE id = %s AND created_by = %s
                """,
                (menu_id, username),
            )
        conn.commit()
    return {"ok": True}


@router.delete("/cooking/menus/{menu_id}/items/{item_id}")
def remove_menu_item(menu_id: int, item_id: int, request: Request, _=Depends(require_auth)):
    username = _current_username(request)
    with get_db() as conn:
        with conn.cursor() as cursor:
            _ensure_menu_owner(cursor, menu_id, username)
            cursor.execute(
                "DELETE FROM `love_cooking_menu_items` WHERE id = %s AND menu_id = %s",
                (item_id, menu_id),
            )
            if getattr(cursor, "rowcount", 0) == 0:
                raise HTTPException(status_code=404, detail="菜单项不存在")
        conn.commit()
    return {"ok": True}
