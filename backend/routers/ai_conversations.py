"""AI 对话会话管理路由 — 持久化对话历史"""
import logging
from fastapi import APIRouter, Depends, Request, Query
from pydantic import BaseModel, Field
from typing import Optional

from ..database import get_db
from ..dependencies import require_auth, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai/conversations", tags=["ai-conversations"])


# ==================== 请求/响应模型 ====================

class ConversationCreate(BaseModel):
    provider: str = Field(..., pattern="^(claude|codex|glm|grok)$")
    title: str = Field(default="新对话", max_length=100)


class TitleUpdate(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)


class MessageSave(BaseModel):
    role: str = Field(..., pattern="^(user|assistant|system)$")
    content: str = Field(..., min_length=1)


# ==================== 路由 ====================

@router.get("")
def list_conversations(
    request: Request,
    provider: str = Query(..., pattern="^(claude|codex|glm|grok)$"),
    _=Depends(require_auth),
):
    """获取某供应商的会话列表（按更新时间倒序）"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, title, created_at, updated_at
                   FROM ai_conversations
                   WHERE username = %s AND provider = %s
                   ORDER BY updated_at DESC
                   LIMIT 50""",
                (user.username, provider),
            )
            rows = cur.fetchall()
    return [
        {"id": r[0], "title": r[1], "created_at": str(r[2]), "updated_at": str(r[3])}
        for r in rows
    ]


@router.post("")
def create_conversation(body: ConversationCreate, request: Request, _=Depends(require_auth)):
    """新建会话"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO ai_conversations (username, provider, title) VALUES (%s, %s, %s)",
                (user.username, body.provider, body.title),
            )
            conn.commit()
            conv_id = cur.lastrowid
    return {"id": conv_id, "title": body.title, "provider": body.provider}


@router.get("/{conv_id}/messages")
def get_messages(conv_id: int, request: Request, _=Depends(require_auth)):
    """获取某会话的全部消息"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            # 先校验归属
            cur.execute(
                "SELECT id FROM ai_conversations WHERE id = %s AND username = %s",
                (conv_id, user.username),
            )
            if not cur.fetchone():
                return {"error": "会话不存在", "messages": []}

            cur.execute(
                """SELECT id, role, content, created_at
                   FROM ai_messages
                   WHERE conversation_id = %s
                   ORDER BY created_at ASC""",
                (conv_id,),
            )
            rows = cur.fetchall()
    return {
        "messages": [
            {"id": r[0], "role": r[1], "content": r[2], "created_at": str(r[3])}
            for r in rows
        ]
    }


@router.delete("/{conv_id}")
def delete_conversation(conv_id: int, request: Request, _=Depends(require_auth)):
    """删除会话及其所有消息"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            # 校验归属
            cur.execute(
                "SELECT id FROM ai_conversations WHERE id = %s AND username = %s",
                (conv_id, user.username),
            )
            if not cur.fetchone():
                return {"error": "会话不存在"}

            cur.execute("DELETE FROM ai_messages WHERE conversation_id = %s", (conv_id,))
            cur.execute("DELETE FROM ai_conversations WHERE id = %s", (conv_id,))
            conn.commit()
    return {"ok": True}


@router.put("/{conv_id}/title")
def update_title(conv_id: int, body: TitleUpdate, request: Request, _=Depends(require_auth)):
    """修改会话标题"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE ai_conversations SET title = %s WHERE id = %s AND username = %s",
                (body.title, conv_id, user.username),
            )
            conn.commit()
    return {"ok": True}


@router.post("/{conv_id}/messages")
def save_messages(conv_id: int, messages: list[MessageSave], request: Request, _=Depends(require_auth)):
    """批量保存消息到指定会话（前端在 SSE 结束后调用）"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            # 校验归属
            cur.execute(
                "SELECT id FROM ai_conversations WHERE id = %s AND username = %s",
                (conv_id, user.username),
            )
            if not cur.fetchone():
                return {"error": "会话不存在"}

            for msg in messages:
                cur.execute(
                    "INSERT INTO ai_messages (conversation_id, role, content) VALUES (%s, %s, %s)",
                    (conv_id, msg.role, msg.content),
                )
            # 更新会话活跃时间
            cur.execute(
                "UPDATE ai_conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (conv_id,),
            )
            conn.commit()
    return {"ok": True, "count": len(messages)}


@router.get("/search")
def search_conversations(
    request: Request,
    q: str = Query(..., min_length=1, max_length=100),
    provider: str = Query(..., pattern="^(claude|codex|glm|grok)$"),
    _=Depends(require_auth),
):
    """搜索消息内容，返回匹配的会话"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT DISTINCT c.id, c.title, c.updated_at
                   FROM ai_conversations c
                   JOIN ai_messages m ON m.conversation_id = c.id
                   WHERE c.username = %s AND c.provider = %s
                     AND m.content LIKE %s
                   ORDER BY c.updated_at DESC
                   LIMIT 20""",
                (user.username, provider, f"%{q}%"),
            )
            rows = cur.fetchall()
    return [
        {"id": r[0], "title": r[1], "updated_at": str(r[2])}
        for r in rows
    ]
