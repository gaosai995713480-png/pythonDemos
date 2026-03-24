"""快递物流查询路由"""
from fastapi import APIRouter, Depends
from ..database import get_config, set_config
from ..dependencies import require_role
from ..services.kuaidi100 import query_express, detect_company, COMPANY_LIST

router = APIRouter(prefix="/api", tags=["express"])

# 快递100配置键名
_KUAIDI100_CUSTOMER_KEY = "KUAIDI100_CUSTOMER"
_KUAIDI100_KEY_KEY = "KUAIDI100_KEY"


def _normalize_config_value(value) -> str:
    """将配置值归一化为可安全写入的字符串。"""
    if not isinstance(value, str):
        return ""
    return value.strip()


@router.get("/express/query")
def express_query(num: str, com: str, phone: str = ""):
    """查询快递物流信息"""
    if not num or not com:
        return {"status": "error", "message": "快递单号和快递公司不能为空"}
    customer = get_config(_KUAIDI100_CUSTOMER_KEY)
    key = get_config(_KUAIDI100_KEY_KEY)
    result = query_express(
        com=com,
        num=num,
        customer=customer,
        key=key,
        phone=phone,
    )
    return result


@router.get("/express/detect")
def express_detect(num: str):
    """根据单号自动识别快递公司"""
    if not num:
        return {"auto": []}
    companies = detect_company(num)
    return {"auto": companies}


@router.get("/express/companies")
def express_companies():
    """获取常用快递公司列表"""
    return {"companies": COMPANY_LIST}


@router.get("/express/config")
def express_config(_=Depends(require_role("admin"))):
    """获取快递100配置状态（仅返回是否已配置，不暴露真实值）"""
    customer = get_config(_KUAIDI100_CUSTOMER_KEY)
    key = get_config(_KUAIDI100_KEY_KEY)
    return {
        "customer_configured": bool(customer),
        "key_configured": bool(key),
    }


@router.post("/express/config")
def update_express_config(body: dict, _=Depends(require_role("admin"))):
    """更新快递100 API 配置"""
    updated = 0
    customer = _normalize_config_value(body.get("customer"))
    key = _normalize_config_value(body.get("key"))
    if customer:
        set_config(_KUAIDI100_CUSTOMER_KEY, customer)
        updated += 1
    if key:
        set_config(_KUAIDI100_KEY_KEY, key)
        updated += 1
    return {"ok": True, "updated": updated}
