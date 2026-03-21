"""认证路由"""
from fastapi import APIRouter, Request, Response, Depends
from ..database import get_db
from ..config import settings
from ..dependencies import (
    is_authenticated, create_session, destroy_session,
    set_login_cookie, clear_login_cookie,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/status")
def auth_status(request: Request):
    if is_authenticated(request):
        return {"authenticated": True}
    return Response(
        content='{"authenticated": false}',
        status_code=401,
        media_type="application/json",
    )


@router.post("/login")
def auth_login(request: Request, response: Response, body: dict = {}):
    password = str(body.get("password", "")).strip()
    if not password:
        return Response(
            content='{"error": "请输入密码"}',
            status_code=400,
            media_type="application/json",
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT 1 FROM `{settings.auth_table}` WHERE password = %s LIMIT 1",
                (password,),
            )
            ok = cursor.fetchone() is not None

    if not ok:
        return Response(
            content='{"error": "密码是我们故事开始的日子"}',
            status_code=401,
            media_type="application/json",
        )

    token = create_session()
    response = Response(
        content='{"ok": true}',
        media_type="application/json",
    )
    set_login_cookie(response, token)
    return response


@router.post("/logout")
def auth_logout(request: Request):
    destroy_session(request)
    response = Response(
        content='{"ok": true}',
        media_type="application/json",
    )
    clear_login_cookie(response)
    return response
