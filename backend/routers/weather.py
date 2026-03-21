"""天气代理路由"""
from fastapi import APIRouter
from ..config import settings
from ..services.gaode import proxy_gaode

router = APIRouter(prefix="/api", tags=["weather"])


@router.get("/weather")
def weather(city: str = "420100", extensions: str = "base"):
    if not city or city == "[]":
        city = "420100"
    if extensions not in ("base", "all"):
        extensions = "base"
    result = proxy_gaode(
        "https://restapi.amap.com/v3/weather/weatherInfo",
        {"city": city, "extensions": extensions},
        settings.gaode_key,
    )
    return result


@router.get("/weather/district")
def district(keywords: str = "中国", subdistrict: int = 1):
    result = proxy_gaode(
        "https://restapi.amap.com/v3/config/district",
        {"keywords": keywords, "subdistrict": str(subdistrict)},
        settings.gaode_key,
    )
    return result


@router.get("/weather/locate")
def locate():
    result = proxy_gaode(
        "https://restapi.amap.com/v3/ip",
        {},
        settings.gaode_key,
    )
    
    def get_str(k: str) -> str:
        v = result.get(k, "")
        if isinstance(v, list) and len(v) == 0:
            return ""
        return str(v)

    return {
        "adcode": get_str("adcode"),
        "city": get_str("city"),
        "province": get_str("province"),
    }
