"""
Agent 工具注册中心 + 内置工具实现

使用装饰器注册工具，支持动态发现和调用。
架构预留扩展：未来可通过此模块注册自定义工具。
"""
import json
import logging
from typing import Callable, Any

from ..database import get_db, get_config
from ..config import settings
from ..services.gaode import proxy_gaode
from ..services.kuaidi100 import query_express, detect_company

logger = logging.getLogger(__name__)

# ==================== 工具注册表 ====================

_tool_registry: dict[str, dict] = {}


def register_tool(
    name: str,
    description: str,
    parameters: dict,
    required: list[str] | None = None,
):
    """工具注册装饰器"""
    def decorator(fn: Callable):
        _tool_registry[name] = {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": parameters,
                "required": required or list(parameters.keys()),
            },
            "handler": fn,
        }
        return fn
    return decorator


def get_all_tools() -> list[dict]:
    """获取所有已注册工具的定义（不含 handler）"""
    return [
        {
            "name": t["name"],
            "description": t["description"],
            "parameters": t["parameters"],
        }
        for t in _tool_registry.values()
    ]


def get_tools_for_openai() -> list[dict]:
    """转换为 OpenAI function calling 格式"""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            },
        }
        for t in _tool_registry.values()
    ]


def get_tools_for_anthropic() -> list[dict]:
    """转换为 Anthropic tool_use 格式"""
    return [
        {
            "name": t["name"],
            "description": t["description"],
            "input_schema": t["parameters"],
        }
        for t in _tool_registry.values()
    ]


async def execute_tool(name: str, arguments: dict) -> str:
    """执行指定工具，返回 JSON 字符串结果"""
    tool = _tool_registry.get(name)
    if not tool:
        return json.dumps({"error": f"未知工具: {name}"}, ensure_ascii=False)

    handler = tool["handler"]
    try:
        result = handler(**arguments)
        if isinstance(result, str):
            return result
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception as e:
        logger.error("工具 %s 执行失败: %s", name, e, exc_info=True)
        return json.dumps({"error": f"工具执行失败: {str(e)}"}, ensure_ascii=False)


# ==================== 内置工具 ====================


@register_tool(
    name="weather_query",
    description="查询指定城市的天气预报。可以查询当前天气或未来几天的预报。",
    parameters={
        "city": {
            "type": "string",
            "description": "城市名称或行政区划代码（adcode），例如 '杭州' 或 '330100'",
        },
        "forecast": {
            "type": "boolean",
            "description": "是否查询未来预报。false=当前天气，true=未来几天预报",
        },
    },
    required=["city"],
)
def tool_weather_query(city: str, forecast: bool = False) -> dict:
    """查询天气"""
    # 如果传入中文城市名，先查 adcode
    adcode = city
    if not city.isdigit():
        district_result = proxy_gaode(
            "https://restapi.amap.com/v3/config/district",
            {"keywords": city, "subdistrict": "0"},
            settings.gaode_key,
        )
        districts = district_result.get("districts", [])
        if districts:
            adcode = districts[0].get("adcode", city)
            city_name = districts[0].get("name", city)
        else:
            return {"error": f"未找到城市: {city}"}
    else:
        city_name = city

    extensions = "all" if forecast else "base"
    result = proxy_gaode(
        "https://restapi.amap.com/v3/weather/weatherInfo",
        {"city": adcode, "extensions": extensions},
        settings.gaode_key,
    )

    if forecast:
        forecasts = result.get("forecasts", [])
        if forecasts:
            casts = forecasts[0].get("casts", [])
            return {
                "city": city_name,
                "forecasts": [
                    {
                        "date": c.get("date"),
                        "dayweather": c.get("dayweather"),
                        "nightweather": c.get("nightweather"),
                        "daytemp": c.get("daytemp"),
                        "nighttemp": c.get("nighttemp"),
                    }
                    for c in casts
                ],
            }
    else:
        lives = result.get("lives", [])
        if lives:
            live = lives[0]
            return {
                "city": city_name,
                "weather": live.get("weather"),
                "temperature": live.get("temperature"),
                "humidity": live.get("humidity"),
                "winddirection": live.get("winddirection"),
                "windpower": live.get("windpower"),
                "reporttime": live.get("reporttime"),
            }

    return {"city": city_name, "message": "未获取到天气数据"}


@register_tool(
    name="express_query",
    description="查询快递物流信息。需要提供快递单号，可选提供快递公司编码。",
    parameters={
        "num": {
            "type": "string",
            "description": "快递单号",
        },
        "com": {
            "type": "string",
            "description": "快递公司编码，如 'shunfeng'(顺丰)、'yuantong'(圆通)、'zhongtong'(中通)、'yunda'(韵达)、'jd'(京东)。不确定时可留空，系统会自动识别。",
        },
    },
    required=["num"],
)
def tool_express_query(num: str, com: str = "") -> dict:
    """查询快递"""
    # 自动识别快递公司
    if not com:
        companies = detect_company(num)
        if companies:
            com = companies[0].get("comCode", "")
        if not com:
            return {"error": "无法识别快递公司，请提供快递公司编码"}

    customer = get_config("KUAIDI100_CUSTOMER")
    key = get_config("KUAIDI100_KEY")
    if not customer or not key:
        return {"error": "快递查询服务未配置"}

    result = query_express(com=com, num=num, customer=customer, key=key)
    # 精简返回，只取最近5条物流
    if isinstance(result, dict) and "data" in result:
        data = result.get("data", [])
        return {
            "status": result.get("state", ""),
            "company": result.get("com", com),
            "number": num,
            "recent_tracks": data[:5] if isinstance(data, list) else [],
        }
    return result


@register_tool(
    name="timeline_query",
    description="查询纪念日和重要事件时间轴。返回所有记录的纪念日、约会、旅行等重要时刻。",
    parameters={},
    required=[],
)
def tool_timeline_query() -> list:
    """查询时间线"""
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT event_date, title, content, icon FROM `{settings.timeline_table}` ORDER BY event_date DESC LIMIT 20"
            )
            rows = cursor.fetchall()
    return [
        {
            "date": r[0].isoformat() if r[0] else None,
            "title": r[1],
            "content": r[2],
            "icon": r[3] or "💕",
        }
        for r in rows
    ]


@register_tool(
    name="music_search",
    description="搜索音乐歌曲。可以按关键词搜索歌曲，也可以查看当前共享歌单。",
    parameters={
        "action": {
            "type": "string",
            "enum": ["search", "playlist"],
            "description": "'search'=按关键词搜索新歌, 'playlist'=查看当前共享歌单",
        },
        "keyword": {
            "type": "string",
            "description": "搜索关键词（仅 action=search 时需要）",
        },
    },
    required=["action"],
)
def tool_music_search(action: str, keyword: str = "") -> dict | list:
    """搜索音乐"""
    if action == "playlist":
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    f"SELECT song_name, artist, platform FROM `{settings.music_table}` ORDER BY sort_order ASC, created_at DESC LIMIT 20"
                )
                rows = cursor.fetchall()
        return {
            "playlist": [
                {"title": r[0], "artist": r[1], "platform": r[2] or "netease"}
                for r in rows
            ]
        }
    elif action == "search" and keyword:
        from ..services.meting import call_meting
        result = call_meting("search", platform="netease", keyword=keyword, limit="5")
        data = result.get("data", []) if result.get("ok") else []
        return {"results": data[:5]}
    return {"error": "请提供搜索关键词"}


@register_tool(
    name="mood_query",
    description="查询心情记录。可以查看某月的心情打卡记录。",
    parameters={
        "year": {"type": "integer", "description": "年份，如 2026"},
        "month": {"type": "integer", "description": "月份，如 4"},
    },
    required=[],
)
def tool_mood_query(year: int = None, month: int = None) -> dict:
    """查询心情"""
    import datetime
    today = datetime.date.today()
    if year is None:
        year = today.year
    if month is None:
        month = today.month

    start_date = f"{year:04d}-{month:02d}-01"
    if month == 12:
        end_date = f"{year + 1:04d}-01-01"
    else:
        end_date = f"{year:04d}-{month + 1:02d}-01"

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT mood_date, emoji, note, level FROM `{settings.mood_table}` WHERE mood_date >= %s AND mood_date < %s ORDER BY mood_date ASC",
                (start_date, end_date),
            )
            rows = cursor.fetchall()
    return {
        "year": year,
        "month": month,
        "records": [
            {
                "date": r[0].isoformat() if r[0] else None,
                "emoji": r[1],
                "note": r[2],
                "level": r[3],
            }
            for r in rows
        ],
    }


@register_tool(
    name="wish_list",
    description="查看星空许愿墙上的所有心愿。",
    parameters={},
    required=[],
)
def tool_wish_list() -> dict:
    """查看心愿"""
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"SELECT content, created_at FROM `{settings.wish_table}` ORDER BY created_at DESC LIMIT 20"
            )
            rows = cursor.fetchall()
    return {
        "wishes": [
            {"content": r[0], "created_at": r[1].isoformat() if r[1] else None}
            for r in rows
        ]
    }


@register_tool(
    name="photo_search",
    description="搜索相册中的照片。返回照片列表及数量信息。",
    parameters={
        "limit": {
            "type": "integer",
            "description": "返回照片数量上限，默认10",
        },
    },
    required=[],
)
def tool_photo_search(limit: int = 10) -> dict:
    """搜索相册"""
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT filename, created_at FROM love_photos ORDER BY created_at DESC LIMIT %s",
                (limit,),
            )
            rows = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) FROM love_photos")
            total = cursor.fetchone()[0]
    return {
        "total_photos": total,
        "recent_photos": [
            {"filename": r[0], "created_at": r[1].isoformat() if r[1] else None}
            for r in rows
        ],
    }


# ==================== 记忆工具 ====================

# 上下文变量：当前用户名（由 Agent Loop 在调用前设置）
_current_username: str = ""


def set_current_username(username: str):
    """设置当前工具调用上下文的用户名"""
    global _current_username
    _current_username = username


@register_tool(
    name="remember_fact",
    description="记住关于用户的重要信息。当用户提到个人偏好、重要日期、人物关系等值得长期记忆的信息时，主动调用此工具保存。",
    parameters={
        "content": {
            "type": "string",
            "description": "要记住的事实内容，例如 '女朋友生日是3月15日'、'喜欢吃火锅'、'住在杭州'",
        },
        "category": {
            "type": "string",
            "enum": ["general", "date", "preference", "person"],
            "description": "事实分类: general(一般), date(日期), preference(偏好), person(人物)",
        },
    },
    required=["content"],
)
def tool_remember_fact(content: str, category: str = "general") -> dict:
    """主动记忆用户事实"""
    from .user_memory import save_fact
    if not _current_username:
        return {"error": "无法确定当前用户"}
    fact_id = save_fact(_current_username, content, category, source="tool")
    return {"ok": True, "id": fact_id, "message": f"已记住: {content}"}


@register_tool(
    name="recall_facts",
    description="回忆关于用户的已知信息。当需要了解用户的个人信息、偏好或历史记录时调用。",
    parameters={
        "keyword": {
            "type": "string",
            "description": "搜索关键词（可选），用于筛选相关记忆",
        },
    },
    required=[],
)
def tool_recall_facts(keyword: str = "") -> dict:
    """检索用户记忆"""
    from .user_memory import get_user_facts
    if not _current_username:
        return {"error": "无法确定当前用户"}
    facts = get_user_facts(_current_username, limit=30)
    if keyword:
        keyword_lower = keyword.lower()
        facts = [f for f in facts if keyword_lower in f["content"].lower()]
    return {
        "total": len(facts),
        "facts": [{"content": f["content"], "category": f["category"]} for f in facts],
    }

