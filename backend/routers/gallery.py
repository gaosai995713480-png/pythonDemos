"""画廊路由 - 密码验证"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..database import verify_page_password
from ..dependencies import require_auth

router = APIRouter(prefix="/api/gallery", tags=["gallery"])


class VerifyRequest(BaseModel):
    password: str


@router.post("/verify")
def verify_gallery_password(body: VerifyRequest, _=Depends(require_auth)):
    """验证画廊密码"""
    if verify_page_password("gallery", body.password):
        return {"ok": True}
    return {"ok": False, "error": "密码错误"}
