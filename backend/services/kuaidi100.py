"""
快递100 API 服务
文档: https://api.kuaidi100.com/document/5f0ffb5fbc8da837cbd8aefc
"""
import hashlib
import json
import logging
import urllib.request
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

# 常用快递公司编码（快递100官方 comCode）
COMPANY_LIST = [
    {"code": "shunfeng", "name": "顺丰速运"},
    {"code": "zhongtong", "name": "中通快递"},
    {"code": "yuantong", "name": "圆通速递"},
    {"code": "shentong", "name": "申通快递"},
    {"code": "yunda", "name": "韵达快递"},
    {"code": "jd", "name": "京东物流"},
    {"code": "ems", "name": "EMS"},
    {"code": "youzhengguonei", "name": "邮政快递包裹"},
    {"code": "huitongkuaidi", "name": "百世快递"},
    {"code": "debangkuaidi", "name": "德邦快递"},
    {"code": "jtexpress", "name": "极兔速递"},
    {"code": "danniao", "name": "菜鸟速递"},
    {"code": "annengwuliu", "name": "安能物流"},
    {"code": "fengwang", "name": "丰网速运"},
    {"code": "zhongyouex", "name": "众邮快递"},
]


def _md5(text: str) -> str:
    """生成 MD5 签名（32位大写）"""
    return hashlib.md5(text.encode("utf-8")).hexdigest().upper()


def query_express(
    com: str, num: str, customer: str, key: str, phone: str = ""
) -> dict:
    """
    调用快递100实时查询接口。

    Args:
        com: 快递公司编码（如 'shunfeng'）
        num: 快递单号
        customer: 快递100授权码
        key: 快递100密钥
        phone: 手机号后4位（顺丰等必填）

    Returns:
        快递100 API 返回的 JSON 数据
    """
    if not customer or not key:
        return {"status": "error", "message": "未配置快递100 API，请管理员在快递查询页面底部配置授权码和密钥"}

    param = {
        "com": com,
        "num": num,
        "resultv2": "1",
    }
    if phone:
        param["phone"] = phone

    param_str = json.dumps(param)
    sign = _md5(param_str + key + customer)

    post_data = urlencode({
        "customer": customer,
        "sign": sign,
        "param": param_str,
    }).encode("utf-8")

    url = "https://poll.kuaidi100.com/poll/query.do"
    try:
        req = urllib.request.Request(
            url,
            data=post_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "xiguasaiLove/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        logger.warning("快递100查询异常: %s", e)
        return {"status": "error", "message": f"查询失败: {e}"}


def detect_company(num: str) -> list:
    """
    根据快递单号自动识别快递公司。

    Args:
        num: 快递单号

    Returns:
        匹配的快递公司列表 [{"comCode": "shunfeng", "noCount": 100, ...}, ...]
    """
    url = f"https://www.kuaidi100.com/autonumber/autoComNum?resultv2=1&text={num}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "xiguasaiLove/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("auto", [])
    except Exception as e:
        logger.warning("快递公司识别异常: %s", e)
        return []
