"""用户管理路由 - 管理员专属"""
from fastapi import APIRouter, Depends
from ..config import settings
from ..database import get_db, get_config, set_config
from ..dependencies import require_role

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("")
def list_users(_=Depends(require_role("admin"))):
    """获取所有用户列表"""
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, username, role, disabled, created_at, last_login_at FROM `{settings.users_table}` ORDER BY id"
            )
            rows = cursor.fetchall()
    return [
        {
            "id": r[0],
            "username": r[1],
            "role": r[2],
            "disabled": bool(r[3]),
            "created_at": str(r[4]),
            "last_login_at": str(r[5]) if r[5] else None,
        }
        for r in rows
    ]


@router.post("/{user_id}/toggle")
def toggle_user(user_id: int, _=Depends(require_role("admin"))):
    """禁用/启用用户（不允许禁用 admin）"""
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"UPDATE `{settings.users_table}` SET disabled = NOT disabled WHERE id = %s AND role != 'admin'",
                (user_id,),
            )
        conn.commit()
    return {"ok": True}


@router.get("/invite-code")
def get_invite_code(_=Depends(require_role("admin"))):
    """获取当前邀请码"""
    return {"code": get_config("INVITE_CODE") or ""}


@router.post("/invite-code")
def update_invite_code(body: dict, _=Depends(require_role("admin"))):
    """修改邀请码"""
    code = str(body.get("code", "")).strip()
    if not code:
        return {"ok": False, "error": "邀请码不能为空"}
    set_config("INVITE_CODE", code)
    return {"ok": True}
