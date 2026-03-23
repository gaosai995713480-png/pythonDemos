"""认证路由 - 登录/注册/状态"""
import json
from fastapi import APIRouter, Request, Response
from ..database import get_db, get_config
from ..config import settings
from ..dependencies import (
    UserInfo, get_current_user,
    create_session, destroy_session,
    set_login_cookie, clear_login_cookie,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/status")
def auth_status(request: Request):
    user = get_current_user(request)
    if user:
        return {"authenticated": True, "username": user.username, "role": user.role}
    return Response(
        content='{"authenticated": false}',
        status_code=401,
        media_type="application/json",
    )


@router.post("/login")
def auth_login(request: Request, body: dict = {}):
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", "")).strip()
    if not username or not password:
        return Response(
            content='{"error": "请输入用户名和密码"}',
            status_code=400,
            media_type="application/json",
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT id, role, disabled FROM `{settings.users_table}` WHERE username = %s AND password = %s LIMIT 1",
                (username, password),
            )
            row = cursor.fetchone()

    if not row:
        return Response(
            content='{"error": "用户名或密码错误"}',
            status_code=401,
            media_type="application/json",
        )
    if row[2]:  # disabled
        return Response(
            content='{"error": "账号已被禁用"}',
            status_code=403,
            media_type="application/json",
        )

    token = create_session(UserInfo(username=username, role=row[1]))
    resp = Response(
        content=json.dumps({"ok": True, "username": username, "role": row[1]}),
        media_type="application/json",
    )
    set_login_cookie(resp, token)
    return resp


@router.post("/register")
def auth_register(request: Request, body: dict = {}):
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", "")).strip()
    invite_code = str(body.get("invite_code", "")).strip()

    if not username or not password or not invite_code:
        return Response(
            content='{"error": "请填写所有字段"}',
            status_code=400,
            media_type="application/json",
        )
    if len(username) < 2 or len(username) > 20:
        return Response(
            content='{"error": "用户名长度 2-20 个字符"}',
            status_code=400,
            media_type="application/json",
        )
    if len(password) < 4 or len(password) > 50:
        return Response(
            content='{"error": "密码长度 4-50 个字符"}',
            status_code=400,
            media_type="application/json",
        )

    # 校验邀请码
    valid_code = get_config("INVITE_CODE")
    if not valid_code or invite_code != valid_code:
        return Response(
            content='{"error": "邀请码无效"}',
            status_code=403,
            media_type="application/json",
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT 1 FROM `{settings.users_table}` WHERE username = %s",
                (username,),
            )
            if cursor.fetchone():
                return Response(
                    content='{"error": "用户名已被注册"}',
                    status_code=409,
                    media_type="application/json",
                )
            cursor.execute(
                f"INSERT INTO `{settings.users_table}` (username, password, role) VALUES (%s, %s, 'visitor')",
                (username, password),
            )
        conn.commit()

    # 注册后自动登录
    token = create_session(UserInfo(username=username, role="visitor"))
    resp = Response(
        content=json.dumps({"ok": True, "username": username, "role": "visitor"}),
        media_type="application/json",
    )
    set_login_cookie(resp, token)
    return resp


@router.post("/logout")
def auth_logout(request: Request):
    destroy_session(request)
    response = Response(
        content='{"ok": true}',
        media_type="application/json",
    )
    clear_login_cookie(response)
    return response
