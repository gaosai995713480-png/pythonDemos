"""
认证依赖 - session cookie 认证 + 角色权限
"""
import secrets
from dataclasses import dataclass
from fastapi import Request, HTTPException, Response

SESSION_COOKIE_NAME = "love_session"


@dataclass
class UserInfo:
    username: str
    role: str  # 'admin' | 'visitor'
    gallery_unlocked: bool = False


_sessions: dict[str, UserInfo] = {}


def get_session_token(request: Request) -> str:
    """从 cookie 中获取 session token"""
    return request.cookies.get(SESSION_COOKIE_NAME, "")


def get_current_user(request: Request) -> UserInfo | None:
    """获取当前登录用户信息"""
    token = get_session_token(request)
    if token:
        return _sessions.get(token)
    return None


def is_authenticated(request: Request) -> bool:
    """检查是否已登录"""
    return get_current_user(request) is not None


def require_auth(request: Request) -> None:
    """认证依赖：未登录则 401"""
    if not get_current_user(request):
        raise HTTPException(status_code=401, detail="unauthorized")


def require_role(role: str):
    """权限依赖工厂：要求指定角色"""
    def _checker(request: Request):
        user = get_current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="unauthorized")
        if user.role != role:
            raise HTTPException(status_code=403, detail="权限不足")
    return _checker


def require_gallery_access(request: Request) -> None:
    """要求当前登录会话已解锁画廊"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="unauthorized")
    if not user.gallery_unlocked:
        raise HTTPException(status_code=403, detail="画廊未解锁")


def create_session(user_info: UserInfo) -> str:
    """创建新 session，绑定用户信息"""
    token = secrets.token_urlsafe(32)
    _sessions[token] = user_info
    return token


def destroy_session(request: Request) -> None:
    """销毁 session"""
    token = get_session_token(request)
    if token:
        _sessions.pop(token, None)


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
