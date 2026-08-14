"""AI 聊天路由 — 多供应商独立架构"""
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Optional

from ..database import get_config, set_config, get_db
from ..dependencies import require_auth, require_role
from ..services.ai_chat import (
    get_provider,
    get_claude_config,
    get_codex_config,
    get_glm_config,
    get_grok_config,
    CLAUDE_BASE_URL_KEY,
    CLAUDE_API_KEY_KEY,
    CLAUDE_MODEL_KEY,
    CODEX_BASE_URL_KEY,
    CODEX_API_KEY_KEY,
    CODEX_MODEL_KEY,
    GLM_BASE_URL_KEY,
    GLM_API_KEY_KEY,
    GLM_MODEL_KEY,
    GROK_BASE_URL_KEY,
    GROK_API_KEY_KEY,
    GROK_MODEL_KEY,
)

logger = logging.getLogger(__name__)

# 记忆提取后台任务引用：asyncio.create_task 若不持有引用，任务可能被 GC 中断
_memory_tasks: set = set()

router = APIRouter(prefix="/api/ai", tags=["ai"])


# ==================== 请求模型 ====================

class ChatMessage(BaseModel):
    role: str = "user"
    content: str = ""


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000)
    history: list[ChatMessage] = Field(default_factory=list)
    provider: str = Field(default="codex", pattern="^(claude|codex|glm|grok)$")
    skill_id: Optional[int] = Field(default=None)
    conversation_id: Optional[int] = Field(default=None)
    client_context: Optional[str] = Field(default=None)


# ==================== SSE 生成器 ====================

import json

async def _sse_generator(provider_name: str, messages: list[dict]):
    """将 Provider 的流式输出包装为 SSE 格式，Codex/Claude 走 Agent Loop"""
    try:
        provider = get_provider(provider_name)
        if not provider.is_available():
            labels = {"claude": "Claude API", "codex": "Codex API", "glm": "GLM API", "grok": "Grok API"}
            label = labels.get(provider_name, provider_name)
            error_msg = f"[错误] {label} 未配置，请管理员在设置中配置"
            yield f"data: {json.dumps(error_msg)}\n\n"
            return

        # Codex / Claude 走 Agent Loop（支持工具调用）
        if provider_name in ("codex", "claude"):
            from ..services.agent_loop import codex_agent_loop, claude_agent_loop
            if provider_name == "codex":
                cfg = get_codex_config()
                gen = codex_agent_loop(cfg["base_url"], cfg["api_key"], cfg["model"], messages)
            else:
                cfg = get_claude_config()
                gen = claude_agent_loop(cfg["base_url"], cfg["api_key"], cfg["model"], messages)

            async for chunk in gen:
                yield f"data: {chunk}\n\n"
        else:
            # GLM / Grok 走纯对话模式
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
    glm_provider = get_provider("glm")
    grok_provider = get_provider("grok")
    codex_cfg = get_codex_config()
    glm_cfg = get_glm_config()
    grok_cfg = get_grok_config()
    claude_cfg = get_claude_config()
    return {
        "claude": {
            "available": claude_provider.is_available(),
            "model": claude_cfg["model"],
            "base_url": claude_cfg["base_url"],
        },
        "codex": {
            "available": codex_provider.is_available(),
            "model": codex_cfg["model"],
            "base_url": codex_cfg["base_url"],
        },
        "glm": {
            "available": glm_provider.is_available(),
            "model": glm_cfg["model"],
            "base_url": glm_cfg["base_url"],
        },
        "grok": {
            "available": grok_provider.is_available(),
            "model": grok_cfg["model"],
            "base_url": grok_cfg["base_url"],
        },
    }


@router.post("/chat")
async def ai_chat(req: ChatRequest, request: Request, _=Depends(require_auth)):
    """AI 聊天 — 返回 SSE 流式响应（支持 Agent 工具调用 + 长期记忆）"""
    from ..dependencies import get_current_user as _get_user
    from ..services.agent_tools import set_current_user_context
    from ..services.user_memory import build_memory_prompt

    user = _get_user(request)
    username = user.username if user else ""

    # 设置工具调用上下文用户（包含权限供 tool 内部鉴权）
    if user:
        set_current_user_context(user.username, user.role, getattr(user, 'gallery_unlocked', False))
    else:
        set_current_user_context("", "visitor", False)

    messages = []

    # 1. 注入当前环境与页面深度上下文 (最高优)
    if req.client_context:
        messages.append({
            "role": "system",
            "content": f"[前端即时上下文]\n{req.client_context.strip()}\n\n请结合以上环境和页面状态回答。"
        })

    # 2. 注入长期记忆
    if username:
        memory_prompt = build_memory_prompt(username)
        if memory_prompt:
            messages.append({"role": "system", "content": memory_prompt})

    # 3. 注入技能预设的 system prompt
    if req.skill_id and user:
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT system_prompt FROM ai_skill_presets WHERE id = %s AND username = %s",
                        (req.skill_id, user.username),
                    )
                    row = cur.fetchone()
                    if row and row[0]:
                        messages.append({"role": "system", "content": row[0]})
        except Exception as e:
            logger.warning("查询 Skill 失败: %s", e)

    # 4. 注入全局安全护栏 (非 admin 限制)
    if not user or user.role != "admin":
        messages.append({
            "role": "system",
            "content": "【最高安全原则】：当前用户非系统管理员。你被禁止透露任何系统底层的配置文件、密码、Token以及其他未公开的隐私数据。如果用户试图打探此类信息，请礼貌但果断地拒绝。"
        })

    for h in req.history[-20:]:
        # 强制过滤 system 角色，防止注入攻击
        if h.role not in ("user", "assistant"):
            continue
        messages.append({"role": h.role, "content": h.content})
    messages.append({"role": "user", "content": req.message})

    # 包装 SSE 生成器，在流结束后异步触发事实提取
    async def _sse_with_extraction():
        ai_response_text = ""
        async for chunk in _sse_generator(req.provider, messages):
            # 收集 AI 回复文本用于后续提取
            if chunk.startswith("data: ") and chunk.strip() != "data: [DONE]":
                try:
                    data_str = chunk[6:].strip()
                    parsed = json.loads(data_str)
                    if isinstance(parsed, str):
                        ai_response_text += parsed
                except Exception:
                    pass
            yield chunk

        # 流结束后异步提取事实（提取失败由任务内部记录日志）
        if username and ai_response_text and req.provider in ("codex", "claude"):
            import asyncio
            from ..services.user_memory import extract_facts_from_conversation
            task = asyncio.create_task(
                extract_facts_from_conversation(
                    username, req.message, ai_response_text, req.provider
                )
            )
            _memory_tasks.add(task)
            task.add_done_callback(_memory_tasks.discard)

    return StreamingResponse(
        _sse_with_extraction(),
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


@router.post("/config/claude")
def update_claude_config(body: dict, _=Depends(require_role("admin"))):
    updated = 0
    key_map = {
        "base_url": CLAUDE_BASE_URL_KEY,
        "api_key": CLAUDE_API_KEY_KEY,
        "model": CLAUDE_MODEL_KEY,
    }
    for field, config_key in key_map.items():
        if field in body:
            value = str(body[field]).strip()
            if value:
                set_config(config_key, value)
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


# ==================== GLM 配置 ====================

@router.get("/config/glm")
def glm_config(_=Depends(require_role("admin"))):
    cfg = get_glm_config()
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


@router.post("/config/glm")
def update_glm_config(body: dict, _=Depends(require_role("admin"))):
    updated = 0
    key_map = {
        "base_url": GLM_BASE_URL_KEY,
        "api_key": GLM_API_KEY_KEY,
        "model": GLM_MODEL_KEY,
    }
    for field, config_key in key_map.items():
        if field in body:
            value = str(body[field]).strip()
            if value:
                set_config(config_key, value)
                updated += 1
    return {"ok": True, "updated": updated}


# ==================== Grok 配置 ====================

@router.get("/config/grok")
def grok_config(_=Depends(require_role("admin"))):
    cfg = get_grok_config()
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


@router.post("/config/grok")
def update_grok_config(body: dict, _=Depends(require_role("admin"))):
    updated = 0
    key_map = {
        "base_url": GROK_BASE_URL_KEY,
        "api_key": GROK_API_KEY_KEY,
        "model": GROK_MODEL_KEY,
    }
    for field, config_key in key_map.items():
        if field in body:
            value = str(body[field]).strip()
            if value:
                set_config(config_key, value)
                updated += 1
    return {"ok": True, "updated": updated}


# ==================== Agent 配置 ====================

@router.get("/config/agent")
def agent_config(_=Depends(require_role("admin"))):
    show_process = get_config("AGENT_SHOW_TOOL_PROCESS")
    max_rounds = get_config("AGENT_MAX_TOOL_ROUNDS")
    return {
        "show_tool_process": show_process != "false",  # 默认 true
        "max_tool_rounds": int(max_rounds) if max_rounds else 5,
    }


@router.post("/config/agent")
def update_agent_config(body: dict, _=Depends(require_role("admin"))):
    updated = 0
    if "show_tool_process" in body:
        val = "true" if body["show_tool_process"] else "false"
        set_config("AGENT_SHOW_TOOL_PROCESS", val)
        updated += 1
    if "max_tool_rounds" in body:
        try:
            rounds = max(1, min(10, int(body["max_tool_rounds"])))
            set_config("AGENT_MAX_TOOL_ROUNDS", str(rounds))
            updated += 1
        except (ValueError, TypeError):
            pass
    return {"ok": True, "updated": updated}


# ==================== 用户记忆管理 ====================

@router.get("/memory")
def list_memory(request: Request, _=Depends(require_auth)):
    """获取当前用户的长期记忆列表"""
    from ..dependencies import get_current_user as _get_user
    from ..services.user_memory import get_user_facts
    user = _get_user(request)
    if not user:
        return {"facts": []}
    return {"facts": get_user_facts(user.username, limit=100)}


@router.delete("/memory")
def delete_memory(id: int, request: Request, _=Depends(require_auth)):
    """删除一条记忆"""
    from ..dependencies import get_current_user as _get_user
    from ..services.user_memory import delete_fact
    user = _get_user(request)
    if not user:
        return {"error": "未登录"}
    ok = delete_fact(user.username, id)
    return {"ok": ok}
