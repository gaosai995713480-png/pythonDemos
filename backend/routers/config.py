"""系统配置路由（Cookie 管理等）"""
from fastapi import APIRouter, Depends
from ..database import get_all_cookies, set_config, _COOKIE_ENV_KEYS
from ..dependencies import require_auth

router = APIRouter(prefix="/api/config", tags=["config"])

# Cookie key 对应的平台显示名
_PLATFORM_LABELS = {
    "METING_NETEASE_COOKIE": "网易云音乐",
    "METING_TENCENT_COOKIE": "腾讯音乐/QQ音乐",
    "METING_KUGOU_COOKIE": "酷狗音乐",
    "METING_KUWO_COOKIE": "酷我音乐",
}


def _mask_cookie(value: str) -> str:
    """脱敏显示 Cookie：只显示前10位和后6位"""
    if not value or len(value) < 20:
        return value
    return value[:10] + "****" + value[-6:]


@router.get("/cookies")
def get_cookies(_=Depends(require_auth)):
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
def update_cookies(body: dict, _=Depends(require_auth)):
    """更新音乐平台 Cookie 配置"""
    updated = 0
    for key in _COOKIE_ENV_KEYS:
        if key in body:
            value = str(body[key]).strip()
            set_config(key, value)
            updated += 1
    return {"ok": True, "updated": updated}
