"""AI 技能预设 CRUD 路由 — 用户级"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..database import get_db
from ..dependencies import get_current_user, require_auth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai/skills", tags=["ai-skills"])


# ==================== 请求模型 ====================

class SkillCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    icon: str = Field(default="🤖", max_length=10)
    system_prompt: str = Field(..., min_length=1, max_length=50000)


class SkillUpdate(BaseModel):
    name: str = Field(None, min_length=1, max_length=50)
    icon: str = Field(None, max_length=10)
    system_prompt: str = Field(None, min_length=1, max_length=50000)


# ==================== 路由 ====================

@router.get("")
def list_skills(request: Request, _=Depends(require_auth)):
    """获取当前用户的所有技能预设"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, name, icon, system_prompt, created_at FROM ai_skill_presets WHERE username = %s ORDER BY id",
                (user.username,),
            )
            rows = cur.fetchall()
    return [
        {"id": r[0], "name": r[1], "icon": r[2], "system_prompt": r[3], "created_at": str(r[4])}
        for r in rows
    ]


@router.post("")
def create_skill(body: SkillCreate, request: Request, _=Depends(require_auth)):
    """创建新技能预设"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            # 限制每用户最多 20 个技能
            cur.execute(
                "SELECT COUNT(*) FROM ai_skill_presets WHERE username = %s",
                (user.username,),
            )
            if cur.fetchone()[0] >= 20:
                raise HTTPException(status_code=400, detail="最多创建 20 个技能预设")

            cur.execute(
                "INSERT INTO ai_skill_presets (username, name, icon, system_prompt) VALUES (%s, %s, %s, %s)",
                (user.username, body.name, body.icon, body.system_prompt),
            )
            new_id = cur.lastrowid
        conn.commit()
    return {"ok": True, "id": new_id}


@router.put("/{skill_id}")
def update_skill(skill_id: int, body: SkillUpdate, request: Request, _=Depends(require_auth)):
    """更新技能预设（仅限本人）"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM ai_skill_presets WHERE id = %s AND username = %s",
                (skill_id, user.username),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="技能不存在或无权修改")

            updates, params = [], []
            if body.name is not None:
                updates.append("name = %s"); params.append(body.name)
            if body.icon is not None:
                updates.append("icon = %s"); params.append(body.icon)
            if body.system_prompt is not None:
                updates.append("system_prompt = %s"); params.append(body.system_prompt)

            if updates:
                params.append(skill_id)
                cur.execute(f"UPDATE ai_skill_presets SET {', '.join(updates)} WHERE id = %s", params)
        conn.commit()
    return {"ok": True}


@router.delete("/{skill_id}")
def delete_skill(skill_id: int, request: Request, _=Depends(require_auth)):
    """删除技能预设（仅限本人）"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM ai_skill_presets WHERE id = %s AND username = %s",
                (skill_id, user.username),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="技能不存在或无权删除")
        conn.commit()
    return {"ok": True}


@router.get("/{skill_id}")
def get_skill(skill_id: int, request: Request, _=Depends(require_auth)):
    """获取单个技能详情（仅限本人）"""
    user = get_current_user(request)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, name, icon, system_prompt, created_at FROM ai_skill_presets WHERE id = %s AND username = %s",
                (skill_id, user.username),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="技能不存在")
    return {"id": row[0], "name": row[1], "icon": row[2], "system_prompt": row[3], "created_at": str(row[4])}
