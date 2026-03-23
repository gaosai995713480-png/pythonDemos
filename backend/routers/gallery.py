"""画廊路由 - 密码验证"""
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from ..database import verify_page_password
from ..dependencies import get_current_user, require_auth

router = APIRouter(prefix="/api/gallery", tags=["gallery"])


class VerifyRequest(BaseModel):
    password: str


@router.post("/verify")
def verify_gallery_password(body: VerifyRequest, request: Request, _=Depends(require_auth)):
    """验证画廊密码"""
    if verify_page_password("gallery", body.password):
        user = get_current_user(request)
        if user:
            user.gallery_unlocked = True
        return {"ok": True}
    return {"ok": False, "error": "密码错误"}
