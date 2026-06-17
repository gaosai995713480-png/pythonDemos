from fastapi.testclient import TestClient

from backend.main import app
from backend.tripstar.config import TripStarSettings


client = TestClient(app)


def test_tripstar_xhs_status_reports_configured(monkeypatch):
    from backend.tripstar import router as tripstar_router

    monkeypatch.setattr(
        tripstar_router,
        "get_tripstar_settings",
        lambda: TripStarSettings(enable_xhs=True, xhs_cookie="a1=test; web_session=session"),
    )

    response = client.get("/api/tripstar/xhs/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is True
    assert payload["configured"] is True
    assert payload["cookie_length"] > 10


def test_tripstar_xhs_search_returns_normalized_notes(monkeypatch):
    from backend.tripstar import router as tripstar_router

    monkeypatch.setattr(
        tripstar_router,
        "get_tripstar_settings",
        lambda: TripStarSettings(enable_xhs=True, xhs_cookie="a1=test; web_session=session"),
    )

    def fake_search_notes(self, keyword, limit):
        assert keyword == "武汉 美食"
        assert limit == 2
        return [
            {
                "id": "note-1",
                "title": "武汉三天两夜避坑攻略",
                "desc": "黄鹤楼和户部巷可以放在同一天，晚上去江汉路。",
                "liked_count": 128,
                "cover_url": "https://example.com/cover.jpg",
                "note_url": "https://www.xiaohongshu.com/explore/note-1",
                "author": {"nickname": "旅行薯"},
            }
        ]

    monkeypatch.setattr(tripstar_router.XhsService, "search_notes", fake_search_notes)

    response = client.get("/api/tripstar/xhs/search?city=武汉&keyword=美食&limit=2")

    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is True
    assert payload["configured"] is True
    assert payload["query"] == "武汉 美食"
    assert payload["items"][0]["title"] == "武汉三天两夜避坑攻略"
    assert payload["items"][0]["author"]["nickname"] == "旅行薯"


def test_tripstar_xhs_search_requires_enabled_switch(monkeypatch):
    from backend.tripstar import router as tripstar_router

    monkeypatch.setattr(
        tripstar_router,
        "get_tripstar_settings",
        lambda: TripStarSettings(enable_xhs=False, xhs_cookie="a1=test"),
    )

    response = client.get("/api/tripstar/xhs/search?city=武汉&keyword=美食")

    assert response.status_code == 503
    assert response.json()["detail"] == "TripStar 小红书功能未启用"


def test_tripstar_xhs_search_requires_cookie(monkeypatch):
    from backend.tripstar import router as tripstar_router

    monkeypatch.setattr(
        tripstar_router,
        "get_tripstar_settings",
        lambda: TripStarSettings(enable_xhs=True, xhs_cookie=""),
    )

    response = client.get("/api/tripstar/xhs/search?city=武汉&keyword=美食")

    assert response.status_code == 503
    assert response.json()["detail"] == "TripStar 小红书 Cookie 未配置"
