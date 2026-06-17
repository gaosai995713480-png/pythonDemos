from backend.tripstar.config import TripStarSettings
from backend.tripstar.models.schemas import TripStarRequest
from backend.tripstar.real_planner import RealTripStarPlanner


class FakeLLMClient:
    def __init__(self):
        self.prompts = []

    def chat_json(self, *, system_prompt, user_prompt):
        self.prompts.append({"system": system_prompt, "user": user_prompt})
        return {
            "overview": "基于小红书与高德候选生成的武汉真实规划。",
            "days": [
                {
                    "day": 1,
                    "title": "武汉文化初见",
                    "summary": "从黄鹤楼和户部巷开始，兼顾地标与美食。",
                    "attractions": [
                        {
                            "name": "黄鹤楼",
                            "address": "武汉市武昌区蛇山西山坡特1号",
                            "duration": "2小时",
                            "description": "小红书用户提到适合上午登楼避开人流。",
                            "reservation_required": False,
                        },
                        {
                            "name": "户部巷",
                            "address": "武汉市武昌区自由路",
                            "duration": "1.5小时",
                            "description": "适合午餐体验热干面和豆皮。",
                            "reservation_required": False,
                        },
                    ],
                    "meals": [{"type": "午餐", "name": "户部巷小吃", "budget": "80元/人"}],
                    "transportation": "步行和地铁组合。",
                    "hotel_suggestion": "住在武昌核心区。",
                }
            ],
            "budget": {
                "currency": "CNY",
                "total_estimate": "600-900元/人",
                "items": [{"category": "餐饮", "amount": "200元/人"}],
            },
            "weather": {"summary": "出行前再次确认天气。", "tips": ["准备雨具"]},
            "overall_suggestions": "热门景点尽量错峰。",
        }


class FakeXhsService:
    def search_notes(self, keyword, limit):
        assert "武汉" in keyword
        return [
            {
                "title": "武汉三天两夜避坑攻略",
                "desc": "黄鹤楼上午去，户部巷适合午餐，晚上可以去江汉路。",
                "liked_count": 128,
                "note_url": "https://www.xiaohongshu.com/explore/demo",
                "author": {"nickname": "旅行薯"},
            }
        ]


class FakeAmapService:
    def __init__(self):
        self.poi_keywords = []
        self.geocode_keywords = []
        self.route_points = []

    def search_poi(self, city, keyword, limit):
        self.poi_keywords.append(keyword)
        return [
            {
                "name": "黄鹤楼",
                "address": "武汉市武昌区蛇山西山坡特1号",
                "location": {"longitude": 114.302656, "latitude": 30.544872},
            },
            {
                "name": "户部巷",
                "address": "武汉市武昌区自由路",
                "location": {"longitude": 114.299327, "latitude": 30.547268},
            },
        ]

    def geocode(self, city, keyword):
        self.geocode_keywords.append(keyword)
        locations = {
            "黄鹤楼": {"longitude": 114.302656, "latitude": 30.544872},
            "户部巷": {"longitude": 114.299327, "latitude": 30.547268},
        }
        return {
            "name": keyword,
            "address": f"{city}{keyword}",
            "location": locations[keyword],
            "amap_id": keyword,
        }

    def route_many(self, points, mode):
        self.route_points.append([point["name"] for point in points])
        return {
            "mode": mode,
            "distance_meters": 415,
            "duration_seconds": 300,
            "polyline": [[points[0]["longitude"], points[0]["latitude"]], [points[1]["longitude"], points[1]["latitude"]]],
            "segments": [
                {
                    "from": points[0]["name"],
                    "to": points[1]["name"],
                    "distance_meters": 415,
                    "duration_seconds": 300,
                    "polyline": [],
                }
            ],
        }


def test_real_planner_uses_xhs_amap_and_llm_to_build_frontend_plan():
    settings = TripStarSettings(
        mock_mode=False,
        llm_model_id="demo-llm",
        llm_api_key="demo-key",
        llm_base_url="https://llm.example/v1",
        xhs_cookie="a1=test; web_session=session",
        enable_xhs=True,
        amap_web_key="amap-key",
    )
    llm = FakeLLMClient()
    amap = FakeAmapService()
    planner = RealTripStarPlanner(
        settings,
        llm_client=llm,
        xhs_service=FakeXhsService(),
        amap_service=amap,
    )
    progress_events = []

    result = planner.plan(
        TripStarRequest(
            city="武汉",
            start_date="2026-06-01",
            end_date="2026-06-01",
            travel_days=1,
            preferences=["美食", "历史文化"],
            language="zh",
        ),
        lambda stage, message, value: progress_events.append((stage, message, value)),
    )

    assert result["success"] is True
    assert result["mock_mode"] is False
    assert result["real_planner_ready"] is True
    assert result["data"]["source_summary"]["xhs_note_count"] == 1
    assert result["data"]["source_summary"]["poi_candidate_count"] == 2
    assert result["data"]["days"][0]["attractions"][0]["location"]["longitude"] == 114.302656
    assert result["data"]["map_routes"][0]["distance_meters"] == 415
    assert result["graph_data"]["nodes"]
    assert llm.prompts and "小红书" in llm.prompts[0]["user"]
    assert amap.route_points == [["黄鹤楼", "户部巷"]]
    assert progress_events[0][0] == "xhs"
