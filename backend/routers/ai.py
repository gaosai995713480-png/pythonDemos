"""AI 聊天路由 — 双供应商独立架构"""
import logging

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ..database import get_config, set_config
from ..dependencies import require_auth, require_role
from ..services.ai_chat import (
    get_provider,
    get_claude_config,
    get_codex_config,
    CLAUDE_MODEL_KEY,
    CODEX_BASE_URL_KEY,
    CODEX_API_KEY_KEY,
    CODEX_MODEL_KEY,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["ai"])


# ==================== 请求模型 ====================

class ChatMessage(BaseModel):
    role: str = "user"
    content: str = ""


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000)
    history: list[ChatMessage] = Field(default_factory=list)
    provider: str = Field(default="claude", pattern="^(claude|codex)$")


# ==================== SSE 生成器 ====================

import json

async def _sse_generator(provider_name: str, messages: list[dict]):
    """将 Provider 的流式输出包装为 SSE 格式"""
    try:
        provider = get_provider(provider_name)
        if not provider.is_available():
            label = "Claude CLI" if provider_name == "claude" else "Codex API"
            error_msg = f"[错误] {label} 未配置，请管理员在设置中配置"
            yield f"data: {json.dumps(error_msg)}\n\n"
            return

        async for chunk in provider.stream_chat(messages):
            yield f"data: {json.dumps(chunk)}\n\n"

        yield "data: [DONE]\n\n"

    except Exception as e:
        logger.error("AI 聊天异常 [%s]: %s", provider_name, e, exc_info=True)
        yield f"data: {json.dumps('[错误] ' + str(e))}\n\n"


# ==================== 路由 ====================

@router.get("/status")
def ai_status():
    """检查各供应商的可用状态"""
    claude_provider = get_provider("claude")
    codex_provider = get_provider("codex")
    codex_cfg = get_codex_config()
    return {
        "claude": {
            "available": claude_provider.is_available(),
            "model": get_claude_config()["model"],
        },
        "codex": {
            "available": codex_provider.is_available(),
            "model": codex_cfg["model"],
            "base_url": codex_cfg["base_url"],
        },
    }


@router.post("/chat")
async def ai_chat(req: ChatRequest, _=Depends(require_auth)):
    """AI 聊天 — 返回 SSE 流式响应"""
    messages = []
    for h in req.history[-20:]:
        messages.append({"role": h.role, "content": h.content})
    messages.append({"role": "user", "content": req.message})

    return StreamingResponse(
        _sse_generator(req.provider, messages),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ==================== Claude 配置 ====================

@router.get("/config/claude")
def claude_config(_=Depends(require_role("admin"))):
    cfg = get_claude_config()
    return {"model": cfg["model"]}


@router.post("/config/claude")
def update_claude_config(body: dict, _=Depends(require_role("admin"))):
    updated = 0
    if "model" in body and body["model"]:
        set_config(CLAUDE_MODEL_KEY, str(body["model"]).strip())
        updated += 1
    return {"ok": True, "updated": updated}


# ==================== Codex 配置 ====================

@router.get("/config/codex")
def codex_config(_=Depends(require_role("admin"))):
    cfg = get_codex_config()
    api_key = cfg["api_key"]
    masked = ""
    if api_key:
        masked = api_key[:8] + "****" + api_key[-4:] if len(api_key) > 16 else "****"
    return {
        "base_url": cfg["base_url"],
        "api_key_masked": masked,
        "api_key_configured": bool(api_key),
        "model": cfg["model"],
    }


@router.post("/config/codex")
def update_codex_config(body: dict, _=Depends(require_role("admin"))):
    updated = 0
    key_map = {
        "base_url": CODEX_BASE_URL_KEY,
        "api_key": CODEX_API_KEY_KEY,
        "model": CODEX_MODEL_KEY,
    }
    for field, config_key in key_map.items():
        if field in body:
            value = str(body[field]).strip()
            if value:
                set_config(config_key, value)
                updated += 1
    return {"ok": True, "updated": updated}
