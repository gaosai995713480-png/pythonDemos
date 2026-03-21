"""共享歌单路由"""
from fastapi import APIRouter, Depends
from ..database import get_db
from ..config import settings
from ..dependencies import require_auth
from ..services.meting import call_meting, METING_PLATFORMS

router = APIRouter(prefix="/api", tags=["music"])


@router.get("/music")
def list_music():
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, song_name, artist, netease_id, sort_order, created_at, platform FROM `{settings.music_table}` ORDER BY sort_order ASC, created_at DESC"
            )
            rows = cursor.fetchall()
    result = []
    for r in rows:
        item = {
            "id": r[0], "title": r[1], "artist": r[2], "netease_id": r[3],
            "sort_order": r[4],
            "created_at": r[5].isoformat() if r[5] else None,
        }
        try:
            item["platform"] = r[6]
        except IndexError:
            item["platform"] = "netease"
        result.append(item)
    return result


@router.post("/music")
def add_music(body: dict, _=Depends(require_auth)):
    netease_id = str(body.get("netease_id", body.get("id", ""))).strip()
    if not netease_id:
        return {"error": "netease_id or id is required"}, 400

    platform = str(body.get("platform", "netease")).strip()
    if platform not in METING_PLATFORMS:
        platform = "netease"

    song_name = str(body.get("title", body.get("song_name", ""))).strip()
    artist = str(body.get("artist", "")).strip()

    if not song_name or not artist:
        info = call_meting("song", platform=platform, id=netease_id)
        if info.get("ok"):
            data = info.get("data", {})
            if isinstance(data, list) and data:
                data = data[0]
            if isinstance(data, dict):
                if not song_name:
                    song_name = data.get("name", "未知歌曲")
                if not artist:
                    a = data.get("artist", [])
                    artist = ", ".join(a) if isinstance(a, list) else str(a) if a else "未知歌手"
        if not song_name:
            song_name = "未知歌曲"
        if not artist:
            artist = "未知歌手"

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO `{settings.music_table}` (song_name, artist, netease_id, platform) VALUES (%s, %s, %s, %s)",
                (song_name, artist, netease_id, platform),
            )
            row_id = cursor.lastrowid
        conn.commit()
    return {"ok": True, "id": row_id}


@router.delete("/music")
def delete_music(id: int, _=Depends(require_auth)):
    if id <= 0:
        return {"error": "invalid id"}, 400
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"DELETE FROM `{settings.music_table}` WHERE id = %s", (id,)
            )
            affected = cursor.rowcount
        conn.commit()
    if not affected:
        return {"error": "not found"}, 404
    return {"ok": True}


@router.get("/music/search")
def search_music(keyword: str = "", platform: str = "netease", limit: int = 10):
    if not keyword:
        return {"error": "keyword is required"}, 400
    if platform not in METING_PLATFORMS:
        platform = "netease"
    result = call_meting("search", platform=platform, keyword=keyword, limit=str(limit))
    data = result.get("data", []) if result.get("ok") else []
    return data


@router.get("/music/url")
def music_url(id: str = "", platform: str = "netease"):
    if not id:
        return {"error": "id is required"}, 400
    if platform not in METING_PLATFORMS:
        platform = "netease"
    result = call_meting("url", platform=platform, id=id)
    url = ""
    if result.get("ok"):
        data = result.get("data", {})
        url = data.get("url", "") if isinstance(data, dict) else ""
    if not url and platform == "netease":
        url = f"https://music.163.com/song/media/outer/url?id={id}.mp3"
    return {"url": url}


@router.get("/music/lyric")
def music_lyric(id: str = "", platform: str = "netease"):
    if not id:
        return {"error": "id is required"}, 400
    if platform not in METING_PLATFORMS:
        platform = "netease"
    result = call_meting("lyric", platform=platform, id=id)
    lyric_data = {"lyric": "", "tlyric": ""}
    if result.get("ok"):
        data = result.get("data", {})
        if isinstance(data, dict):
            lyric_data["lyric"] = data.get("lyric", "")
            lyric_data["tlyric"] = data.get("tlyric", "")
    return lyric_data
