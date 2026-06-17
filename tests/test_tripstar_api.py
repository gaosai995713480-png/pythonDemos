import time
import logging

from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def test_tripstar_suppresses_httpx_info_logs_to_avoid_key_leakage():
    assert logging.getLogger("httpx").level >= logging.WARNING


def test_tripstar_health_reports_mock_mode_without_llm_token():
    response = client.get("/api/tripstar/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["service"] == "tripstar"
    assert payload["status"] == "healthy"
    assert payload["mock_mode"] is True
    assert payload["task_store"] == "ready"


def test_tripstar_plan_reaches_terminal_state_in_mock_mode():
    response = client.post(
        "/api/tripstar/plan",
        json={
            "city": "西安",
            "start_date": "2026-06-01",
            "end_date": "2026-06-03",
            "travel_days": 3,
            "preferences": ["历史文化", "本地美食"],
            "language": "zh",
        },
    )

    assert response.status_code == 200
    submitted = response.json()
    assert submitted["status"] == "processing"
    assert submitted["task_id"]

    task_id = submitted["task_id"]
    latest = None
    for _ in range(20):
        status_response = client.get(f"/api/tripstar/status/{task_id}")
        assert status_response.status_code == 200
        latest = status_response.json()
        if latest["status"] in {"completed", "failed"}:
            break
        time.sleep(0.05)

    assert latest is not None
    assert latest["status"] == "completed"
    assert latest["progress"] == 100
    assert latest["result"]["success"] is True
    assert latest["result"]["data"]["city"] == "西安"
    assert latest["result"]["data"]["travel_days"] == 3
    assert latest["result"]["data"]["days"], "应生成至少一天行程，避免前端空转"
    first_attraction = latest["result"]["data"]["days"][0]["attractions"][0]
    assert first_attraction["location"]["longitude"]
    assert first_attraction["location"]["latitude"]
    assert latest["result"]["data"]["map_routes"], "应生成地图路线数据，避免前端地图空白"


def test_tripstar_mock_plan_uses_detailed_city_pois_for_wuhan():
    response = client.post(
        "/api/tripstar/plan",
        json={
            "city": "武汉",
            "start_date": "2026-06-01",
            "end_date": "2026-06-03",
            "travel_days": 3,
            "preferences": ["历史文化", "本地美食"],
            "language": "zh",
        },
    )

    assert response.status_code == 200
    task_id = response.json()["task_id"]
    latest = client.get(f"/api/tripstar/status/{task_id}").json()
    plan = latest["result"]["data"]
    attraction_names = [
        attraction["name"]
        for day in plan["days"]
        for attraction in day["attractions"]
    ]

    assert "黄鹤楼" in attraction_names
    assert "湖北省博物馆" in attraction_names
    assert all("城市地标" not in name for name in attraction_names)
    assert all(
        attraction.get("location", {}).get("longitude")
        for day in plan["days"]
        for attraction in day["attractions"]
    )
    assert plan["map_routes"][0]["source"] == "preset"


def test_tripstar_mock_plan_does_not_repeat_same_route_for_long_wuhan_trip():
    response = client.post(
        "/api/tripstar/plan",
        json={
            "city": "武汉",
            "start_date": "2026-06-01",
            "end_date": "2026-06-20",
            "travel_days": 20,
            "preferences": ["历史文化", "本地美食"],
            "language": "zh",
        },
    )

    assert response.status_code == 200
    task_id = response.json()["task_id"]
    latest = client.get(f"/api/tripstar/status/{task_id}").json()
    plan = latest["result"]["data"]
    route_names = [
        " -> ".join(point["name"] for point in route["points"])
        for route in plan["map_routes"]
    ]

    assert len(route_names) == 20
    assert len(set(route_names)) == 20
    assert route_names[4] != "黄鹤楼 -> 户部巷"
    assert all("城市地标" not in route for route in route_names)


def test_tripstar_plan_falls_back_to_mock_when_real_planner_is_not_ready(monkeypatch):
    from backend.tripstar import router as tripstar_router
    from backend.tripstar.config import TripStarSettings

    monkeypatch.setattr(
        tripstar_router,
        "get_tripstar_settings",
        lambda: TripStarSettings(
            mock_mode=False,
            llm_model_id="demo-model",
            llm_api_key="demo-key",
            llm_base_url="https://example.invalid/v1",
        ),
    )

    response = client.post(
        "/api/tripstar/plan",
        json={
            "city": "西安",
            "start_date": "2026-06-01",
            "end_date": "2026-06-02",
            "travel_days": 2,
            "preferences": ["历史文化"],
            "language": "zh",
        },
    )

    assert response.status_code == 200
    task_id = response.json()["task_id"]
    latest = client.get(f"/api/tripstar/status/{task_id}").json()

    assert latest["status"] == "completed"
    assert latest["result"]["success"] is True
    assert latest["result"]["mock_mode"] is True
    assert "真实 TripStar 智能体尚未启用" in latest["result"]["message"]


def test_tripstar_plan_uses_real_planner_when_llm_configured(monkeypatch):
    from backend.tripstar import planner as tripstar_planner
    from backend.tripstar import router as tripstar_router
    from backend.tripstar.config import TripStarSettings

    class FakeRealTripStarPlanner:
        def __init__(self, settings):
            self.settings = settings

        def plan(self, request, progress):
            progress("llm", "正在使用真实 LLM planner...", 50)
            return {
                "success": True,
                "message": "真实 LLM 旅行计划生成成功",
                "data": {
                    "city": request.city,
                    "start_date": request.start_date,
                    "end_date": request.end_date,
                    "travel_days": request.travel_days,
                    "language": request.language,
                    "preferences": request.preferences,
                    "overview": "LLM 生成的攻略",
                    "days": [
                        {
                            "day": 1,
                            "title": "LLM Day 1",
                            "summary": "真实 planner 输出",
                            "attractions": [],
                            "meals": [],
                            "transportation": "",
                            "hotel_suggestion": "",
                        }
                    ],
                    "map_routes": [],
                },
                "graph_data": {"nodes": [], "edges": [], "categories": []},
                "mock_mode": False,
                "real_planner_ready": True,
            }

    monkeypatch.setattr(tripstar_planner, "RealTripStarPlanner", FakeRealTripStarPlanner)
    monkeypatch.setattr(
        tripstar_router,
        "get_tripstar_settings",
        lambda: TripStarSettings(
            mock_mode=False,
            llm_model_id="demo-model",
            llm_api_key="demo-key",
            llm_base_url="https://example.invalid/v1",
        ),
    )

    response = client.post(
        "/api/tripstar/plan",
        json={
            "city": "武汉",
            "start_date": "2026-06-01",
            "end_date": "2026-06-01",
            "travel_days": 1,
            "preferences": ["历史文化"],
            "language": "zh",
        },
    )

    assert response.status_code == 200
    task_id = response.json()["task_id"]
    latest = client.get(f"/api/tripstar/status/{task_id}").json()

    assert latest["status"] == "completed"
    assert latest["result"]["mock_mode"] is False
    assert latest["result"]["real_planner_ready"] is True
    assert latest["result"]["message"] == "真实 LLM 旅行计划生成成功"


def test_tripstar_status_unknown_task_is_404_not_processing_loop():
    response = client.get("/api/tripstar/status/not-exists")

    assert response.status_code == 404
    assert response.json()["detail"] == "TripStar 任务不存在"


def test_tripstar_ws_unknown_task_sends_terminal_failed_snapshot():
    with client.websocket_connect("/api/tripstar/ws/not-exists") as websocket:
        payload = websocket.receive_json()

    assert payload["task_id"] == "not-exists"
    assert payload["status"] == "failed"
    assert payload["progress"] == 100
    assert payload["error"] == "TripStar 任务不存在"
