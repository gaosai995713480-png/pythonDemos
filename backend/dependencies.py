"""
认证依赖 - session cookie 认证
"""
import secrets
from fastapi import Request, HTTPException, Response

SESSION_COOKIE_NAME = "love_session"
_session_tokens: set[str] = set()


def get_session_token(request: Request) -> str:
    """从 cookie 中获取 session token"""
    return request.cookies.get(SESSION_COOKIE_NAME, "")


def is_authenticated(request: Request) -> bool:
    """检查是否已登录"""
    token = get_session_token(request)
    return bool(token and token in _session_tokens)


def require_auth(request: Request) -> None:
    """认证依赖：未登录则 401"""
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="unauthorized")


def create_session() -> str:
    """创建新 session"""
    token = secrets.token_urlsafe(32)
    _session_tokens.add(token)
    return token


def destroy_session(request: Request) -> None:
    """销毁 session"""
    token = get_session_token(request)
    if token:
        _session_tokens.discard(token)


def set_login_cookie(response: Response, token: str) -> None:
    """设置登录 cookie"""
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        path="/",
        httponly=True,
        samesite="lax",
        max_age=2592000,  # 30 天
    )


def clear_login_cookie(response: Response) -> None:
    """清除登录 cookie"""
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
    )
