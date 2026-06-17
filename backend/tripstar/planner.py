"""TripStar 旅行规划执行器。"""
from __future__ import annotations

import time
import math
from typing import Any, Callable

from .config import TripStarSettings
from .models.schemas import TripStarRequest
from .real_planner import RealTripStarPlanner


ProgressCallback = Callable[[str, str, int], None]


CITY_CENTERS: dict[str, tuple[float, float]] = {
    "北京": (116.397128, 39.916527),
    "上海": (121.473701, 31.230416),
    "广州": (113.264385, 23.129112),
    "深圳": (114.057868, 22.543099),
    "西安": (108.939621, 34.343147),
    "杭州": (120.15507, 30.274085),
    "成都": (104.066541, 30.572269),
    "重庆": (106.551556, 29.56301),
    "武汉": (114.305393, 30.593099),
    "南京": (118.796877, 32.060255),
}


CITY_POI_PRESETS: dict[str, list[dict[str, Any]]] = {
    "武汉": [
        {
            "name": "黄鹤楼",
            "address": "武汉市武昌区蛇山西山坡特1号",
            "duration": "2小时",
            "description": "武汉代表性城市地标，适合俯瞰长江与武昌老城，感受历史文化氛围。",
            "location": {"longitude": 114.302656, "latitude": 30.544872},
        },
        {
            "name": "户部巷",
            "address": "武汉市武昌区自由路",
            "duration": "1.5小时",
            "description": "适合安排小吃和夜间散步，可把热干面、豆皮、糊汤粉等本地风味集中体验。",
            "location": {"longitude": 114.299327, "latitude": 30.547268},
        },
        {
            "name": "湖北省博物馆",
            "address": "武汉市武昌区东湖路160号",
            "duration": "3小时",
            "description": "重点看曾侯乙编钟、越王勾践剑等馆藏，历史文化偏好用户优先级很高。",
            "location": {"longitude": 114.367386, "latitude": 30.561738},
        },
        {
            "name": "东湖听涛景区",
            "address": "武汉市武昌区沿湖大道",
            "duration": "2小时",
            "description": "湖边步行节奏轻松，适合把博物馆后的下午安排成低强度自然景观。",
            "location": {"longitude": 114.385491, "latitude": 30.556459},
        },
        {
            "name": "武汉大学",
            "address": "武汉市武昌区八一路299号",
            "duration": "2小时",
            "description": "校园建筑和珞珈山步道适合慢逛，春季可重点关注樱花季预约规则。",
            "location": {"longitude": 114.367318, "latitude": 30.537859},
        },
        {
            "name": "江汉路步行街",
            "address": "武汉市江汉区江汉路",
            "duration": "2小时",
            "description": "汉口商业街区，适合晚餐、咖啡和夜景串联，也方便继续前往江滩。",
            "location": {"longitude": 114.292147, "latitude": 30.584355},
        },
        {
            "name": "汉口江滩",
            "address": "武汉市江岸区沿江大道",
            "duration": "1.5小时",
            "description": "适合傍晚看长江夜景，和江汉路、江汉关一带组合成夜游路线。",
            "location": {"longitude": 114.302516, "latitude": 30.596848},
        },
        {
            "name": "古德寺",
            "address": "武汉市江岸区黄浦大街上滑坡路74号",
            "duration": "1.5小时",
            "description": "建筑风格独特，适合拍照和半日轻量游玩，注意保持安静参观。",
            "location": {"longitude": 114.315164, "latitude": 30.625349},
        },
    ],
    "西安": [
        {
            "name": "西安钟楼",
            "address": "西安市碑林区东西南北四条大街交汇处",
            "duration": "1小时",
            "description": "西安市中心地标，适合作为古城游览起点，夜景也很有辨识度。",
            "location": {"longitude": 108.940174, "latitude": 34.341568},
        },
        {
            "name": "回民街",
            "address": "西安市莲湖区北院门",
            "duration": "1.5小时",
            "description": "集中体验肉夹馍、羊肉泡馍等小吃，适合和钟鼓楼组合安排。",
            "location": {"longitude": 108.939454, "latitude": 34.346814},
        },
        {
            "name": "陕西历史博物馆",
            "address": "西安市雁塔区小寨东路91号",
            "duration": "3小时",
            "description": "历史文化主题核心景点，建议提前预约并预留较完整参观时间。",
            "location": {"longitude": 108.959099, "latitude": 34.219589},
        },
        {
            "name": "大雁塔",
            "address": "西安市雁塔区雁塔路",
            "duration": "1.5小时",
            "description": "唐文化代表景点，适合与大唐不夜城串联成下午到夜间路线。",
            "location": {"longitude": 108.964232, "latitude": 34.218285},
        },
        {
            "name": "西安城墙",
            "address": "西安市碑林区南大街",
            "duration": "2小时",
            "description": "可步行或骑行体验古城格局，傍晚时段光线更适合拍照。",
            "location": {"longitude": 108.943776, "latitude": 34.257609},
        },
        {
            "name": "大唐不夜城",
            "address": "西安市雁塔区慈恩路46号",
            "duration": "2小时",
            "description": "夜间氛围强，适合收尾当天行程，注意人流和返程交通。",
            "location": {"longitude": 108.966071, "latitude": 34.211985},
        },
    ],
}

CITY_POI_SUPPLEMENTS: dict[str, list[dict[str, Any]]] = {
    "武汉": [
        {
            "name": "武汉长江大桥",
            "address": "武汉市武昌区临江大道",
            "duration": "1.5小时",
            "description": "适合安排江景步行和城市地标拍照，可与晴川阁、龟山一带组成半日路线。",
            "location": {"longitude": 114.293583, "latitude": 30.554959},
        },
        {
            "name": "晴川阁",
            "address": "武汉市汉阳区洗马长街86号",
            "duration": "1.5小时",
            "description": "与黄鹤楼隔江相望，适合从另一个角度看长江与武汉三镇格局。",
            "location": {"longitude": 114.287243, "latitude": 30.554213},
        },
        {
            "name": "龟山公园",
            "address": "武汉市汉阳区龟山北路",
            "duration": "2小时",
            "description": "山体不高但视野开阔，适合把晴川阁和长江大桥串联成轻徒步路线。",
            "location": {"longitude": 114.280961, "latitude": 30.558538},
        },
        {
            "name": "昙华林",
            "address": "武汉市武昌区昙华林",
            "duration": "2小时",
            "description": "老街、咖啡馆和历史建筑密集，适合慢逛、拍照和下午茶。",
            "location": {"longitude": 114.302341, "latitude": 30.552948},
        },
        {
            "name": "粮道街",
            "address": "武汉市武昌区粮道街",
            "duration": "1.5小时",
            "description": "本地小吃密集，适合早餐或午餐安排，和昙华林距离较近。",
            "location": {"longitude": 114.309379, "latitude": 30.548528},
        },
        {
            "name": "楚河汉街",
            "address": "武汉市武昌区楚河汉街",
            "duration": "2小时",
            "description": "商业街区和夜景氛围较强，适合晚间吃饭、购物和散步。",
            "location": {"longitude": 114.341849, "latitude": 30.558511},
        },
        {
            "name": "武汉天地",
            "address": "武汉市江岸区芦沟桥路",
            "duration": "2小时",
            "description": "汉口休闲商业街区，适合餐饮、咖啡和轻松夜生活安排。",
            "location": {"longitude": 114.302629, "latitude": 30.607557},
        },
        {
            "name": "黎黄陂路",
            "address": "武汉市江岸区黎黄陂路",
            "duration": "1.5小时",
            "description": "老汉口风貌街区，适合拍照、Citywalk 和了解近代建筑风格。",
            "location": {"longitude": 114.295864, "latitude": 30.588327},
        },
        {
            "name": "归元禅寺",
            "address": "武汉市汉阳区归元寺路20号",
            "duration": "1.5小时",
            "description": "武汉知名寺院，适合文化参观，节假日注意人流。",
            "location": {"longitude": 114.255475, "latitude": 30.546838},
        },
        {
            "name": "琴台大剧院",
            "address": "武汉市汉阳区知音大道7号",
            "duration": "1小时",
            "description": "适合安排外观打卡或结合演出日程，周边可串联月湖和古琴台。",
            "location": {"longitude": 114.266383, "latitude": 30.558928},
        },
        {
            "name": "武汉园博园",
            "address": "武汉市硚口区金南二路8号",
            "duration": "3小时",
            "description": "园林体量较大，适合安排半天慢逛，亲子或轻松游优先级较高。",
            "location": {"longitude": 114.197908, "latitude": 30.635557},
        },
        {
            "name": "汉阳造创意园",
            "address": "武汉市汉阳区龟北路1号",
            "duration": "1.5小时",
            "description": "工业风创意园区，适合拍照和轻量文艺路线。",
            "location": {"longitude": 114.272151, "latitude": 30.557489},
        },
        {
            "name": "武汉美术馆",
            "address": "武汉市江岸区保华街2号",
            "duration": "2小时",
            "description": "适合雨天或文艺主题安排，建议提前确认展览与开放时间。",
            "location": {"longitude": 114.292308, "latitude": 30.584066},
        },
        {
            "name": "江汉关博物馆",
            "address": "武汉市江汉区沿江大道95号",
            "duration": "1.5小时",
            "description": "适合了解汉口开埠历史，可与江汉路、汉口江滩组成一条线。",
            "location": {"longitude": 114.292684, "latitude": 30.579881},
        },
        {
            "name": "宝通禅寺",
            "address": "武汉市武昌区武珞路549号",
            "duration": "1.5小时",
            "description": "闹市中的古寺，适合文化参观和短暂停留。",
            "location": {"longitude": 114.331527, "latitude": 30.527691},
        },
        {
            "name": "武汉植物园",
            "address": "武汉市洪山区鲁磨路特1号",
            "duration": "2.5小时",
            "description": "适合自然主题和慢节奏出行，可与东湖磨山方向串联。",
            "location": {"longitude": 114.421613, "latitude": 30.545709},
        },
        {
            "name": "光谷步行街",
            "address": "武汉市洪山区珞喻路",
            "duration": "2小时",
            "description": "适合晚间商业休闲和餐饮补给，距离东湖东南侧较近。",
            "location": {"longitude": 114.405844, "latitude": 30.506229},
        },
        {
            "name": "东湖磨山景区",
            "address": "武汉市武昌区东湖磨山",
            "duration": "3小时",
            "description": "东湖核心自然景区之一，适合骑行、赏花和湖边步行。",
            "location": {"longitude": 114.411345, "latitude": 30.553156},
        },
        {
            "name": "东湖落雁景区",
            "address": "武汉市洪山区青王公路",
            "duration": "3小时",
            "description": "相对安静的东湖片区，适合自然摄影和低强度散步。",
            "location": {"longitude": 114.455867, "latitude": 30.570322},
        },
        {
            "name": "湖北美术馆",
            "address": "武汉市武昌区东湖路三官殿1号",
            "duration": "1.5小时",
            "description": "和湖北省博物馆距离较近，适合文化展览主题的一日组合。",
            "location": {"longitude": 114.363347, "latitude": 30.561328},
        },
        {
            "name": "武汉科技馆",
            "address": "武汉市江岸区沿江大道91号",
            "duration": "2小时",
            "description": "适合亲子和雨天备用，也可以与江汉关、江滩串联。",
            "location": {"longitude": 114.292159, "latitude": 30.581114},
        },
        {
            "name": "吉庆街",
            "address": "武汉市江岸区吉庆街",
            "duration": "1.5小时",
            "description": "老汉口夜宵氛围较强，适合晚餐后体验本地市井气。",
            "location": {"longitude": 114.292322, "latitude": 30.590802},
        },
        {
            "name": "万松园美食街",
            "address": "武汉市江汉区万松园路",
            "duration": "2小时",
            "description": "武汉本地热门餐饮聚集地，适合专门安排一晚吃虾、烧烤或小馆。",
            "location": {"longitude": 114.271897, "latitude": 30.593725},
        },
        {
            "name": "古琴台",
            "address": "武汉市汉阳区琴台大道10号",
            "duration": "1小时",
            "description": "知音文化相关景点，适合与龟山、琴台大剧院组合。",
            "location": {"longitude": 114.264955, "latitude": 30.554827},
        },
        {
            "name": "汉口里",
            "address": "武汉市硚口区园博园东路",
            "duration": "1.5小时",
            "description": "复古街区风格，适合作为园博园周边的餐饮和拍照补充。",
            "location": {"longitude": 114.208679, "latitude": 30.629619},
        },
        {
            "name": "武汉博物馆",
            "address": "武汉市江汉区青年路373号",
            "duration": "2小时",
            "description": "适合补充城市历史脉络，雨天或交通中转日较友好。",
            "location": {"longitude": 114.255347, "latitude": 30.608104},
        },
        {
            "name": "辛亥革命博物院",
            "address": "武汉市武昌区彭刘杨路258号",
            "duration": "2小时",
            "description": "武昌首义主题核心场馆，适合历史文化偏好的行程。",
            "location": {"longitude": 114.305345, "latitude": 30.539246},
        },
        {
            "name": "首义广场",
            "address": "武汉市武昌区首义路",
            "duration": "1小时",
            "description": "与辛亥革命博物院距离近，适合组成武昌首义历史线。",
            "location": {"longitude": 114.306176, "latitude": 30.538059},
        },
        {
            "name": "中山公园",
            "address": "武汉市江汉区解放大道1265号",
            "duration": "1.5小时",
            "description": "市中心老牌公园，适合轻松散步，也便于和武广商圈组合。",
            "location": {"longitude": 114.272888, "latitude": 30.584992},
        },
        {
            "name": "武商梦时代",
            "address": "武汉市武昌区武珞路598号",
            "duration": "2小时",
            "description": "大型商业综合体，适合雨天、购物或餐饮休整日安排。",
            "location": {"longitude": 114.337973, "latitude": 30.526143},
        },
        {
            "name": "后官湖湿地公园",
            "address": "武汉市蔡甸区彭家山头58号",
            "duration": "3小时",
            "description": "适合安排远一点的自然休闲日，节奏比市区景点更放松。",
            "location": {"longitude": 114.106297, "latitude": 30.536924},
        },
        {
            "name": "木兰天池",
            "address": "武汉市黄陂区长轩岭街石门山",
            "duration": "5小时",
            "description": "偏周边一日游，适合长天数行程中安排自然山水和换节奏。",
            "location": {"longitude": 114.279409, "latitude": 31.127409},
        },
    ],
}

LONG_TRIP_FALLBACK_THEMES = [
    ("老城 Citywalk 深度线", "老街、咖啡馆和历史建筑慢逛，适合补足长线行程里的轻量日。"),
    ("本地早餐与菜市场体验", "以烟火气和本地小吃为主，适合把上午安排得更生活化。"),
    ("江河湖泊散步线", "降低强度，安排湖边或江边步行，适合长旅途中恢复体力。"),
    ("博物馆与展览备用线", "雨天也能执行，适合文化主题用户。"),
    ("夜景与美食收尾线", "把餐饮、夜景和短距离散步组合起来，避免白天过满。"),
    ("周边半日慢游线", "安排到市区外一点的轻度探索，给长天数行程增加变化。"),
]

RESERVATION_REQUIRED_NAMES = {"湖北省博物馆", "陕西历史博物馆", "武汉植物园", "木兰天池"}


class TripStarPlanner:
    """旅行规划执行器。

    当前先提供稳定 mock 闭环；当配置齐全并关闭 mock 后，可在该类中接入迁移后的
    TripStar/HelloAgents 真实 planner，保持路由和前端契约不变。
    """

    def __init__(self, settings: TripStarSettings):
        self.settings = settings

    def plan(self, request: TripStarRequest, progress: ProgressCallback) -> dict[str, Any]:
        if self.settings.effective_mock_mode:
            return self._mock_plan(request, progress)
        try:
            return RealTripStarPlanner(self.settings).plan(request, progress)
        except Exception as exc:
            return self._fallback_to_mock_after_real_error(request, progress, exc)

    def _mock_plan(self, request: TripStarRequest, progress: ProgressCallback) -> dict[str, Any]:
        stages = [
            ("requirements", "正在理解旅行需求...", 20),
            ("attractions", "正在整理城市亮点和景点候选...", 45),
            ("route", "正在编排每日路线和节奏...", 70),
            ("budget", "正在生成预算和提醒事项...", 90),
        ]
        for stage, message, value in stages:
            progress(stage, message, value)
            time.sleep(0.01)

        days = []
        preference_text = "、".join(request.preferences) if request.preferences else "轻松游玩"
        for day_index in range(1, request.travel_days + 1):
            attractions = self._mock_attractions_for_day(request, day_index)
            days.append(
                {
                    "day": day_index,
                    "title": f"{request.city}第 {day_index} 天 · {preference_text}",
                    "summary": f"以{preference_text}为主题，安排早中晚三个节奏清晰的行程段。",
                    "attractions": attractions,
                    "meals": [
                        {"type": "午餐", "name": f"{request.city}本地风味餐", "budget": "80-120元/人"},
                        {"type": "晚餐", "name": "轻松休闲晚餐", "budget": "100-160元/人"},
                    ],
                    "transportation": "建议优先地铁/打车组合，减少跨区折返。",
                    "hotel_suggestion": "选择靠近核心商圈或地铁换乘站的酒店，方便晚间返回。",
                }
            )

        plan_data = {
            "city": request.city,
            "start_date": request.start_date,
            "end_date": request.end_date,
            "travel_days": request.travel_days,
            "language": request.language,
            "preferences": request.preferences,
            "overview": f"这是一份 {request.city} {request.travel_days} 天旅行规划示例。当前为 mock 模式，填入大模型配置后可启用真实 TripStar 智能体。",
            "days": days,
            "budget": {
                "currency": "CNY",
                "total_estimate": f"{request.travel_days * 600}-{request.travel_days * 1000}元/人",
                "items": [
                    {"category": "餐饮", "amount": f"{request.travel_days * 180}-{request.travel_days * 280}元/人"},
                    {"category": "交通", "amount": f"{request.travel_days * 80}-{request.travel_days * 160}元/人"},
                    {"category": "门票", "amount": f"{request.travel_days * 100}-{request.travel_days * 220}元/人"},
                ],
            },
            "weather": {
                "summary": "mock 模式未调用实时天气，请以出行前官方天气为准。",
                "tips": ["提前查看天气变化", "准备舒适步行鞋", "热门景点建议提前预约"],
            },
            "overall_suggestions": "第一阶段已跑通 TripStar 接入闭环；真实模型、小红书和地图能力可通过配置逐步开启。",
        }
        self._attach_mock_map_data(plan_data)
        return {
            "success": True,
            "message": "旅行计划生成成功（mock 模式）",
            "data": plan_data,
            "graph_data": {
                "nodes": [
                    {"id": "city", "name": request.city, "category": "city"},
                    *[
                        {"id": f"day-{day['day']}", "name": day["title"], "category": "day"}
                        for day in days
                    ],
                ],
                "edges": [
                    {"source": "city", "target": f"day-{day['day']}", "label": "包含"}
                    for day in days
                ],
                "categories": [
                    {"name": "city"},
                    {"name": "day"},
                ],
            },
            "mock_mode": True,
        }

    def _fallback_to_mock_after_real_error(
        self,
        request: TripStarRequest,
        progress: ProgressCallback,
        exc: Exception,
    ) -> dict[str, Any]:
        progress("fallback", "真实 TripStar 智能体调用失败，正在切换到安全 mock 规划...", 20)
        result = self._mock_plan(request, progress)
        result["message"] = "真实 TripStar 智能体尚未启用或调用失败，已使用 mock 模式生成旅行计划"
        result["mock_mode"] = True
        result["real_planner_ready"] = False
        result["real_planner_error"] = str(exc)
        return result

    def _mock_attractions_for_day(self, request: TripStarRequest, day_index: int) -> list[dict[str, Any]]:
        presets = self._poi_catalog_for_city(request.city)
        start = (day_index - 1) * 2
        selected = presets[start : start + 2]
        if len(selected) < 2:
            selected = [
                *selected,
                *self._generated_long_trip_attractions(request, start + len(selected), 2 - len(selected)),
            ]

        if selected:
            return [
                {
                    **item,
                    "reservation_required": item["name"] in RESERVATION_REQUIRED_NAMES,
                    "map_source": item.get("map_source") or "preset",
                }
                for item in selected
            ]

        return self._generated_long_trip_attractions(request, start, 2)

    def _poi_catalog_for_city(self, city: str) -> list[dict[str, Any]]:
        return [
            *CITY_POI_PRESETS.get(city, []),
            *CITY_POI_SUPPLEMENTS.get(city, []),
        ]

    def _generated_long_trip_attractions(
        self,
        request: TripStarRequest,
        start_index: int,
        count: int,
    ) -> list[dict[str, Any]]:
        center_lng, center_lat = self._city_center(request.city)
        generated = []
        for offset in range(count):
            item_index = start_index + offset
            theme_name, theme_desc = LONG_TRIP_FALLBACK_THEMES[
                item_index % len(LONG_TRIP_FALLBACK_THEMES)
            ]
            step = item_index + 1
            longitude = round(center_lng + 0.018 * ((step % 7) - 3), 6)
            latitude = round(center_lat + 0.014 * (((step // 2) % 7) - 3), 6)
            generated.append(
                {
                    "name": f"{request.city}{theme_name} {step}",
                    "address": f"{request.city}深度旅行体验区",
                    "duration": "2小时",
                    "description": theme_desc,
                    "reservation_required": False,
                    "map_source": "generated",
                    "location": {"longitude": longitude, "latitude": latitude},
                }
            )
        return generated

    def _attach_mock_map_data(self, plan_data: dict[str, Any]) -> None:
        """为 mock 行程补齐可渲染的地图点位和按天路线。

        这里不主动请求外部高德接口，避免在没有网络或 Key 配置异常时让任务卡住。
        真实地点校准通过 `/api/tripstar/map/*` 接口完成；mock 行程先保证前端地图不空白。
        """
        center_lng, center_lat = self._city_center(str(plan_data.get("city") or ""))
        marker_index = 0
        routes: list[dict[str, Any]] = []

        for day in plan_data.get("days") or []:
            points: list[dict[str, Any]] = []
            for attraction in day.get("attractions") or []:
                marker_index += 1
                existing_location = self._normalize_location(attraction.get("location"))
                if existing_location:
                    location = existing_location
                    attraction["map_source"] = attraction.get("map_source") or "preset"
                else:
                    longitude = round(center_lng + 0.012 * marker_index, 6)
                    latitude = round(center_lat + 0.008 * ((marker_index % 5) - 2), 6)
                    location = {"longitude": longitude, "latitude": latitude}
                    attraction["map_source"] = "mock"
                attraction["location"] = location
                points.append(
                    {
                        "name": attraction.get("name") or f"景点 {marker_index}",
                        "longitude": location["longitude"],
                        "latitude": location["latitude"],
                    }
                )

            if points:
                distance = self._route_distance(points)
                routes.append(
                    {
                        "day": day.get("day"),
                        "mode": "walking",
                        "points": points,
                        "polyline": [[point["longitude"], point["latitude"]] for point in points],
                        "distance_meters": distance,
                        "duration_seconds": max(0, int(distance / 80 * 60)) if distance else 0,
                        "source": "preset" if all(
                            attraction.get("map_source") == "preset"
                            for attraction in day.get("attractions") or []
                        ) else "mock",
                    }
                )

        plan_data["map_center"] = {"longitude": center_lng, "latitude": center_lat}
        plan_data["map_routes"] = routes

    def _city_center(self, city: str) -> tuple[float, float]:
        if city in CITY_CENTERS:
            return CITY_CENTERS[city]

        seed = sum(ord(char) for char in city) if city else 0
        longitude = 104.0 + (seed % 1600) / 100.0
        latitude = 24.0 + (seed % 900) / 100.0
        return round(longitude, 6), round(latitude, 6)

    def _normalize_location(self, location: Any) -> dict[str, float] | None:
        if not isinstance(location, dict):
            return None
        try:
            longitude = float(location.get("longitude", location.get("lng")))
            latitude = float(location.get("latitude", location.get("lat")))
        except (TypeError, ValueError):
            return None
        return {"longitude": longitude, "latitude": latitude}

    def _route_distance(self, points: list[dict[str, Any]]) -> int:
        if len(points) < 2:
            return 0

        distance = 0.0
        for index in range(len(points) - 1):
            distance += self._haversine_meters(points[index], points[index + 1])
        return int(distance)

    def _haversine_meters(self, start: dict[str, Any], end: dict[str, Any]) -> float:
        radius = 6371000
        start_lat = math.radians(float(start["latitude"]))
        end_lat = math.radians(float(end["latitude"]))
        delta_lat = end_lat - start_lat
        delta_lng = math.radians(float(end["longitude"]) - float(start["longitude"]))
        value = (
            math.sin(delta_lat / 2) ** 2
            + math.cos(start_lat) * math.cos(end_lat) * math.sin(delta_lng / 2) ** 2
        )
        return 2 * radius * math.asin(math.sqrt(value))
