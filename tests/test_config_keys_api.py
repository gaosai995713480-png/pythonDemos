from fastapi.testclient import TestClient

from backend.database import get_config, set_config
from backend.dependencies import SESSION_COOKIE_NAME, UserInfo, create_session
from backend.main import app


client = TestClient(app)


def _client_with_role(role: str) -> TestClient:
    local_client = TestClient(app)
    token = create_session(UserInfo(username=f"{role}_tester", role=role))
    local_client.cookies.set(SESSION_COOKIE_NAME, token)
    return local_client


def test_admin_can_upsert_generic_config_key_to_love_config():
    admin_client = _client_with_role("admin")

    response = admin_client.post(
        "/api/config/keys",
        json={
            "key": "TRIPSTAR_TEST_KEY",
            "value": "unit-test-value",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True, "key": "TRIPSTAR_TEST_KEY"}
    assert get_config("TRIPSTAR_TEST_KEY") == "unit-test-value"


def test_non_admin_cannot_upsert_generic_config_key():
    visitor_client = _client_with_role("visitor")

    response = visitor_client.post(
        "/api/config/keys",
        json={
            "key": "TRIPSTAR_VISITOR_TEST_KEY",
            "value": "should-not-write",
        },
    )

    assert response.status_code == 403


def test_config_key_list_masks_values_for_admin():
    admin_client = _client_with_role("admin")
    admin_client.post(
        "/api/config/keys",
        json={"key": "TRIPSTAR_MASK_TEST_KEY", "value": "1234567890abcdef"},
    )

    response = admin_client.get("/api/config/keys")

    assert response.status_code == 200
    payload = response.json()
    item = next(row for row in payload["items"] if row["key"] == "TRIPSTAR_MASK_TEST_KEY")
    assert item["has_value"] is True
    assert item["value"] == ""
    assert item["masked_value"].startswith("1234")
    assert item["masked_value"].endswith("cdef")


def test_tripstar_map_config_reads_frontend_keys_from_love_config_without_leaking_web_key():
    set_config("TRIPSTAR_AMAP_WEB_KEY", "backend-web-key")
    set_config("VITE_TRIPSTAR_AMAP_WEB_JS_KEY", "frontend-js-key")
    set_config("VITE_TRIPSTAR_AMAP_SECURITY_JS_CODE", "frontend-security-code")

    health_response = client.get("/api/tripstar/health")
    map_response = client.get("/api/tripstar/map/config")

    assert health_response.status_code == 200
    assert health_response.json()["amap_configured"] is True
    assert health_response.json()["amap_js_configured"] is True
    assert map_response.status_code == 200
    payload = map_response.json()
    assert payload["configured"] is True
    assert payload["amap_web_js_key"] == "frontend-js-key"
    assert payload["amap_security_js_code"] == "frontend-security-code"
    assert "backend-web-key" not in str(payload)
