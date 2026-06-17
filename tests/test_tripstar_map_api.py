from fastapi.testclient import TestClient

from backend.main import app
from backend.tripstar.config import TripStarSettings


client = TestClient(app)


def _settings_with_amap_key() -> TripStarSettings:
    return TripStarSettings(
        amap_web_key="test-amap-web-key",
        amap_web_js_key="test-js-key",
        amap_security_js_code="test-security-code",
    )


def test_tripstar_geocode_returns_normalized_location(monkeypatch):
    from backend.tripstar import router as tripstar_router

    monkeypatch.setattr(tripstar_router, "get_tripstar_settings", _settings_with_amap_key)

    def fake_geocode(self, city, keyword):
        assert city == "西安"
        assert keyword == "钟楼"
        return {
            "name": "钟楼",
            "address": "陕西省西安市碑林区",
            "location": {"longitude": 108.940174, "latitude": 34.341568},
            "amap_id": "B001D0I2GC",
        }

    monkeypatch.setattr(tripstar_router.AmapService, "geocode", fake_geocode)

    response = client.get("/api/tripstar/map/geocode?city=西安&keyword=钟楼")

    assert response.status_code == 200
    payload = response.json()
    assert payload["configured"] is True
    assert payload["item"]["name"] == "钟楼"
    assert payload["item"]["location"] == {"longitude": 108.940174, "latitude": 34.341568}


def test_tripstar_poi_search_returns_limited_items(monkeypatch):
    from backend.tripstar import router as tripstar_router

    monkeypatch.setattr(tripstar_router, "get_tripstar_settings", _settings_with_amap_key)

    def fake_search_poi(self, city, keyword, limit):
        assert city == "西安"
        assert keyword == "博物馆"
        assert limit == 3
        return [
            {
                "name": "陕西历史博物馆",
                "address": "小寨东路91号",
                "location": {"longitude": 108.959, "latitude": 34.219},
                "amap_id": "B001D0J8",
            }
        ]

    monkeypatch.setattr(tripstar_router.AmapService, "search_poi", fake_search_poi)

    response = client.get("/api/tripstar/map/poi?city=西安&keyword=博物馆&limit=3")

    assert response.status_code == 200
    payload = response.json()
    assert payload["configured"] is True
    assert len(payload["items"]) == 1
    assert payload["items"][0]["name"] == "陕西历史博物馆"


def test_tripstar_route_returns_polyline_for_multiple_points(monkeypatch):
    from backend.tripstar import router as tripstar_router

    monkeypatch.setattr(tripstar_router, "get_tripstar_settings", _settings_with_amap_key)

    def fake_route_many(self, points, mode):
        assert mode == "walking"
        assert [point["name"] for point in points] == ["钟楼", "城墙"]
        return {
            "mode": "walking",
            "distance_meters": 1600,
            "duration_seconds": 1800,
            "polyline": [[108.940174, 34.341568], [108.953493, 34.269036]],
            "segments": [
                {
                    "from": "钟楼",
                    "to": "城墙",
                    "distance_meters": 1600,
                    "duration_seconds": 1800,
                }
            ],
        }

    monkeypatch.setattr(tripstar_router.AmapService, "route_many", fake_route_many)

    response = client.post(
        "/api/tripstar/map/route",
        json={
            "mode": "walking",
            "points": [
                {"name": "钟楼", "longitude": 108.940174, "latitude": 34.341568},
                {"name": "城墙", "longitude": 108.953493, "latitude": 34.269036},
            ],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["configured"] is True
    assert payload["route"]["distance_meters"] == 1600
    assert payload["route"]["polyline"] == [[108.940174, 34.341568], [108.953493, 34.269036]]


def test_tripstar_map_api_requires_backend_amap_key(monkeypatch):
    from backend.tripstar import router as tripstar_router

    monkeypatch.setattr(tripstar_router, "get_tripstar_settings", lambda: TripStarSettings(amap_web_key=""))

    response = client.get("/api/tripstar/map/geocode?city=西安&keyword=钟楼")

    assert response.status_code == 503
    assert response.json()["detail"] == "TripStar 高德 Web 服务 Key 未配置"


def test_tripstar_map_config_rejects_placeholder_frontend_key(monkeypatch):
    from backend.tripstar import router as tripstar_router

    monkeypatch.setattr(
        tripstar_router,
        "get_tripstar_settings",
        lambda: TripStarSettings(
            amap_web_js_key="frontend-js-key",
            amap_security_js_code="real-security-code",
        ),
    )

    response = client.get("/api/tripstar/map/config")

    assert response.status_code == 200
    payload = response.json()
    assert payload["configured"] is False
    assert payload["amap_web_js_key"] == ""
    assert "VITE_TRIPSTAR_AMAP_WEB_JS_KEY" in payload["message"]
