"""系统配置路由（Cookie、API Key 管理等）"""
import re
from fastapi import APIRouter, Depends, HTTPException
from ..database import get_all_configs, get_all_cookies, set_config, _COOKIE_ENV_KEYS
from ..dependencies import require_auth, require_role

router = APIRouter(prefix="/api/config", tags=["config"])

_CONFIG_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,49}$")

# Cookie key 对应的平台显示名
_PLATFORM_LABELS = {
    "METING_NETEASE_COOKIE": "网易云音乐",
    "METING_TENCENT_COOKIE": "腾讯音乐/QQ音乐",
    "METING_KUGOU_COOKIE": "酷狗音乐",
    "METING_KUWO_COOKIE": "酷我音乐",
}

_CONFIG_LABELS = {
    "TRIPSTAR_ENABLED": "TripStar 功能开关",
    "TRIPSTAR_MOCK_MODE": "TripStar Mock 模式",
    "TRIPSTAR_LLM_MODEL_ID": "TripStar 大模型名称",
    "TRIPSTAR_LLM_API_KEY": "TripStar 大模型 API Key",
    "TRIPSTAR_LLM_BASE_URL": "TripStar 大模型 Base URL",
    "TRIPSTAR_LLM_TIMEOUT": "TripStar 大模型超时秒数",
    "TRIPSTAR_AMAP_WEB_KEY": "TripStar 高德 Web 服务 Key",
    "TRIPSTAR_ENABLE_XHS": "TripStar 小红书开关",
    "TRIPSTAR_XHS_COOKIE": "TripStar 小红书 Cookie",
    "TRIPSTAR_GOOGLE_MAPS_API_KEY": "TripStar Google Maps Key",
    "TRIPSTAR_GOOGLE_MAPS_PROXY": "TripStar Google Maps 代理",
    "VITE_TRIPSTAR_AMAP_WEB_JS_KEY": "TripStar 高德 JS API Key",
    "VITE_TRIPSTAR_AMAP_SECURITY_JS_CODE": "TripStar 高德安全密钥",
    "INVITE_CODE": "注册邀请码",
    "CLAUDE_API_KEY": "Claude API Key",
    "CLAUDE_BASE_URL": "Claude Base URL",
    "OSS_ACCESS_KEY_ID": "OSS Access Key ID",
    "OSS_ACCESS_KEY_SECRET": "OSS Access Key Secret",
}

_SECRET_HINTS = ("KEY", "SECRET", "TOKEN", "COOKIE", "PASSWORD")


def _mask_cookie(value: str) -> str:
    """脱敏显示 Cookie：只显示前10位和后6位"""
    if not value or len(value) < 20:
        return value
    return value[:10] + "****" + value[-6:]


def _mask_value(value: str) -> str:
    """配置值统一脱敏显示。"""
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


def _validate_config_key(key: str) -> str:
    key = str(key or "").strip().upper()
    if not _CONFIG_KEY_RE.match(key):
        raise HTTPException(
            status_code=400,
            detail="配置键必须为 2-50 位大写字母、数字或下划线，且以字母开头",
        )
    return key


@router.get("/keys")
def list_config_keys(_=Depends(require_role("admin"))):
    """获取 love_config 中所有配置项（仅管理员，配置值脱敏）。"""
    configs = get_all_configs()
    items = []
    for key, value in configs.items():
        is_secret = any(hint in key for hint in _SECRET_HINTS)
        items.append({
            "key": key,
            "label": _CONFIG_LABELS.get(key, key),
            "value": "",  # 不回传真实配置值，避免浏览器侧泄漏
            "masked_value": _mask_value(value),
            "has_value": bool(value),
            "is_secret": is_secret,
        })
    return {"items": items}


@router.post("/keys")
def upsert_config_key(body: dict, _=Depends(require_role("admin"))):
    """新增或更新 love_config 配置项（仅管理员）。"""
    key = _validate_config_key(body.get("key", ""))
    value = str(body.get("value", "")).strip()
    set_config(key, value)
    return {"ok": True, "key": key}


@router.get("/cookies")
def get_cookies(_=Depends(require_role("admin"))):
    """获取所有音乐平台 Cookie 配置（脱敏显示）"""
    db_cookies = get_all_cookies()
    result = []
    for key in _COOKIE_ENV_KEYS:
        value = db_cookies.get(key, "")
        result.append({
            "key": key,
            "label": _PLATFORM_LABELS.get(key, key),
            "value": "",  # 永远不要将真实 Cookie 下发给前端输入框，防止敏感信息泄漏
            "has_value": bool(value),
        })
    return result


@router.post("/cookies")
def update_cookies(body: dict, _=Depends(require_role("admin"))):
    """更新音乐平台 Cookie 配置"""
    updated = 0
    for key in _COOKIE_ENV_KEYS:
        if key in body:
            value = str(body[key]).strip()
            set_config(key, value)
            updated += 1
    return {"ok": True, "updated": updated}
