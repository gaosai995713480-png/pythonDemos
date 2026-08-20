"""共享歌单路由"""
import json
import time
import logging
from urllib.parse import unquote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, JSONResponse
from ..database import get_db, get_config, set_config
from ..config import settings
from ..dependencies import require_auth, require_role
from ..services.meting import call_meting, METING_PLATFORMS
from ..services.oss_storage import (
    upload_to_oss, get_oss_bucket, delete_from_oss,
)
from ..utils import (
    sanitize_upload_filename, is_audio_filename, audio_mime_type, aligned_expires,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["music"])

# 首页背景音乐配置在 love_config 中的键名（全局唯一，管理员设置，所有登录用户共享）
BGM_CONFIG_KEY = "HOME_BGM"
# 上传音频体积上限，避免超大文件把整个请求体读进内存
MAX_AUDIO_BYTES = 30 * 1024 * 1024


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


def resolve_meting_url(song_id: str, platform: str) -> str:
    """解析在线音乐平台的播放直链，失败时回退网易云外链"""
    result = call_meting("url", platform=platform, id=song_id)
    url = ""
    if result.get("ok"):
        data = result.get("data", {})
        url = data.get("url", "") if isinstance(data, dict) else ""
    if not url and platform == "netease":
        url = f"https://music.163.com/song/media/outer/url?id={song_id}.mp3"
    return url


@router.get("/music/url")
def music_url(id: str = "", platform: str = "netease"):
    if not id:
        return {"error": "id is required"}, 400
    if platform not in METING_PLATFORMS:
        platform = "netease"
    return {"url": resolve_meting_url(id, platform)}


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


# ===== 首页背景音乐（管理员设置，所有登录用户共享）=====

def _load_bgm() -> dict:
    """读取首页 BGM 配置，未设置或损坏时返回空 dict"""
    raw = (get_config(BGM_CONFIG_KEY) or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("首页 BGM 配置不是合法 JSON，已忽略: %r", raw[:100])
        return {}
    return data if isinstance(data, dict) else {}


def _local_audio_url(audio_key: str, storage: str) -> str:
    """把音频存储 key 换成可播放的 URL：OSS 走签名直链，本地走后端接口"""
    if storage == "oss":
        bucket = get_oss_bucket()
        if not bucket:
            return ""
        return bucket.sign_url("GET", f"music/{audio_key}", aligned_expires(), slash_safe=True)
    return f"/api/music/bgm/file/{audio_key}"


def _delete_stored_audio(audio_key: str, storage: str) -> None:
    """删除已存储的音频文件，避免更换 BGM 后留下孤儿文件"""
    if not audio_key:
        return
    if storage == "oss":
        delete_from_oss(f"music/{audio_key}")
        return
    target = settings.music_dir / audio_key
    if target.exists() and target.is_file():
        try:
            target.unlink()
        except OSError as e:
            logger.warning("删除本地音频失败 %s: %s", audio_key, e)


@router.get("/music/bgm")
def get_home_bgm(_=Depends(require_auth)):
    """获取首页背景音乐，供任意已登录用户播放"""
    bgm = _load_bgm()
    source = bgm.get("source", "")
    if source == "meting":
        platform = bgm.get("platform", "netease")
        url = resolve_meting_url(str(bgm.get("song_id", "")), platform)
    elif source == "local":
        platform = ""
        url = _local_audio_url(bgm.get("audio_key", ""), bgm.get("storage", "local"))
    else:
        return {"enabled": False}

    return {
        "enabled": bool(url),
        "source": source,
        "platform": platform,
        "song_id": bgm.get("song_id", ""),
        "title": bgm.get("title", ""),
        "artist": bgm.get("artist", ""),
        "url": url,
    }


@router.put("/music/bgm")
def set_home_bgm(body: dict, _=Depends(require_role("admin"))):
    """设置首页背景音乐：来源为在线音乐平台或已上传的本地音频"""
    source = str(body.get("source", "")).strip()
    if source not in ("meting", "local"):
        return JSONResponse({"error": "source 必须为 meting 或 local"}, status_code=400)

    title = str(body.get("title", "")).strip()
    artist = str(body.get("artist", "")).strip()
    new_bgm = {"source": source, "title": title, "artist": artist}

    if source == "meting":
        song_id = str(body.get("song_id", "")).strip()
        if not song_id:
            return JSONResponse({"error": "song_id 不能为空"}, status_code=400)
        platform = str(body.get("platform", "netease")).strip()
        if platform not in METING_PLATFORMS:
            platform = "netease"
        new_bgm.update({"song_id": song_id, "platform": platform})
    else:
        audio_key = sanitize_upload_filename(str(body.get("audio_key", "")))
        if not audio_key or not is_audio_filename(audio_key):
            return JSONResponse({"error": "audio_key 无效"}, status_code=400)
        storage = "oss" if body.get("storage") == "oss" else "local"
        if storage == "local" and not (settings.music_dir / audio_key).is_file():
            return JSONResponse({"error": "音频文件不存在，请重新上传"}, status_code=400)
        new_bgm.update({"audio_key": audio_key, "storage": storage})

    old = _load_bgm()
    set_config(BGM_CONFIG_KEY, json.dumps(new_bgm, ensure_ascii=False))

    # 换掉旧的本地音频后清理文件；同一个文件被重新选中时不删
    if old.get("source") == "local" and old.get("audio_key") != new_bgm.get("audio_key"):
        _delete_stored_audio(old.get("audio_key", ""), old.get("storage", "local"))

    return {"ok": True}


@router.delete("/music/bgm")
def clear_home_bgm(_=Depends(require_role("admin"))):
    """关闭首页背景音乐"""
    old = _load_bgm()
    set_config(BGM_CONFIG_KEY, "")
    if old.get("source") == "local":
        _delete_stored_audio(old.get("audio_key", ""), old.get("storage", "local"))
    return {"ok": True}


@router.post("/music/bgm/upload")
async def upload_bgm_audio(request: Request, _=Depends(require_role("admin"))):
    """上传本地音频文件，返回存储 key；随后需调用 PUT /api/music/bgm 才会生效"""
    raw_name = unquote(request.headers.get("X-File-Name", "").strip())
    safe_name = sanitize_upload_filename(raw_name)
    if not safe_name or not is_audio_filename(safe_name):
        return JSONResponse({"error": "仅支持 mp3/m4a/aac/wav 格式"}, status_code=400)

    file_data = await request.body()
    if not file_data:
        return JSONResponse({"error": "文件内容为空"}, status_code=400)
    if len(file_data) > MAX_AUDIO_BYTES:
        return JSONResponse(
            {"error": f"文件超过 {MAX_AUDIO_BYTES // 1024 // 1024}MB 上限"}, status_code=413
        )

    # 加时间戳前缀，避免不同歌曲同名文件互相覆盖
    audio_key = f"{int(time.time() * 1000)}_{safe_name}"

    if get_oss_bucket():
        if not upload_to_oss(audio_key, file_data, prefix="music"):
            return JSONResponse({"error": "上传 OSS 失败"}, status_code=500)
        storage = "oss"
    else:
        settings.music_dir.mkdir(parents=True, exist_ok=True)
        (settings.music_dir / audio_key).write_bytes(file_data)
        storage = "local"

    return {"ok": True, "audio_key": audio_key, "storage": storage, "filename": safe_name}


@router.get("/music/bgm/file/{audio_key}")
def get_bgm_file(audio_key: str, _=Depends(require_auth)):
    """未配置 OSS 时提供本地音频文件"""
    safe_key = sanitize_upload_filename(audio_key)
    if not safe_key or not is_audio_filename(safe_key):
        return JSONResponse({"error": "invalid audio key"}, status_code=400)

    target = settings.music_dir / safe_key
    if not target.is_file():
        return JSONResponse({"error": "audio not found"}, status_code=404)

    return FileResponse(target, media_type=audio_mime_type(safe_key))
