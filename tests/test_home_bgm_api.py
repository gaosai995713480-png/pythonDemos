import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.database import get_config, set_config
from backend.dependencies import SESSION_COOKIE_NAME, UserInfo, create_session
from backend.routers import music
from backend.main import app


def _client_with_role(role: str) -> TestClient:
    local_client = TestClient(app)
    token = create_session(UserInfo(username=f"{role}_bgm_tester", role=role))
    local_client.cookies.set(SESSION_COOKIE_NAME, token)
    return local_client


@pytest.fixture
def restore_bgm():
    """用例会改写全局 BGM 配置，跑完还原，避免污染真实环境"""
    original = get_config(music.BGM_CONFIG_KEY)
    yield
    set_config(music.BGM_CONFIG_KEY, original or "")


@pytest.fixture
def local_storage(monkeypatch):
    """强制走本地存储分支，避免测试真的往 OSS 写文件"""
    monkeypatch.setattr(music, "get_oss_bucket", lambda: None)


def test_anonymous_cannot_read_home_bgm():
    assert TestClient(app).get("/api/music/bgm").status_code == 401


def test_visitor_cannot_change_home_bgm():
    visitor = _client_with_role("visitor")

    assert visitor.put("/api/music/bgm", json={"source": "meting", "song_id": "1"}).status_code == 403
    assert visitor.delete("/api/music/bgm").status_code == 403
    assert visitor.post("/api/music/bgm/upload", content=b"x").status_code == 403


def test_upload_rejects_non_audio_file(local_storage):
    admin = _client_with_role("admin")

    response = admin.post(
        "/api/music/bgm/upload",
        content=b"not audio",
        headers={"X-File-Name": "evil.exe"},
    )

    assert response.status_code == 400


def test_upload_rejects_oversized_file(local_storage, monkeypatch):
    monkeypatch.setattr(music, "MAX_AUDIO_BYTES", 10)
    admin = _client_with_role("admin")

    response = admin.post(
        "/api/music/bgm/upload",
        content=b"0123456789abcdef",
        headers={"X-File-Name": "big.mp3"},
    )

    assert response.status_code == 413


def test_set_local_bgm_requires_existing_file(restore_bgm):
    admin = _client_with_role("admin")

    response = admin.put(
        "/api/music/bgm",
        json={"source": "local", "audio_key": "not_uploaded.mp3", "storage": "local"},
    )

    assert response.status_code == 400


def test_admin_uploads_local_audio_and_every_user_gets_same_bgm(local_storage, restore_bgm):
    admin = _client_with_role("admin")

    upload = admin.post(
        "/api/music/bgm/upload",
        content=b"fake-audio-bytes",
        headers={"X-File-Name": "our song.mp3"},
    )
    assert upload.status_code == 200
    audio_key = upload.json()["audio_key"]
    stored = settings.music_dir / audio_key
    assert stored.is_file()

    try:
        assert admin.put(
            "/api/music/bgm",
            json={
                "source": "local",
                "audio_key": audio_key,
                "storage": "local",
                "title": "our song",
                "artist": "本地音乐",
            },
        ).status_code == 200

        # 访客账号读到的是同一首（全局共享，不区分账号）
        visitor_view = _client_with_role("visitor").get("/api/music/bgm").json()
        assert visitor_view["enabled"] is True
        assert visitor_view["title"] == "our song"
        assert visitor_view["url"] == f"/api/music/bgm/file/{audio_key}"

        # 本地降级模式下音频通过后端接口下发，且需要登录
        assert TestClient(app).get(visitor_view["url"]).status_code == 401
        file_res = _client_with_role("visitor").get(visitor_view["url"])
        assert file_res.status_code == 200
        assert file_res.headers["content-type"] == "audio/mpeg"

        # 关闭后不再下发，且本地文件被清理
        assert admin.delete("/api/music/bgm").status_code == 200
        assert admin.get("/api/music/bgm").json() == {"enabled": False}
        assert not stored.exists()
    finally:
        stored.unlink(missing_ok=True)


def test_switching_bgm_removes_previous_local_file(local_storage, restore_bgm):
    admin = _client_with_role("admin")
    upload = admin.post(
        "/api/music/bgm/upload",
        content=b"fake-audio-bytes",
        headers={"X-File-Name": "old.mp3"},
    )
    audio_key = upload.json()["audio_key"]
    old_file = settings.music_dir / audio_key
    admin.put(
        "/api/music/bgm",
        json={"source": "local", "audio_key": audio_key, "storage": "local", "title": "old"},
    )

    try:
        # 换成在线音乐源后，旧的本地文件不应该留成孤儿
        assert admin.put(
            "/api/music/bgm",
            json={"source": "meting", "song_id": "123", "platform": "netease", "title": "new"},
        ).status_code == 200
        assert not old_file.exists()
    finally:
        old_file.unlink(missing_ok=True)


def test_meting_bgm_returns_resolved_url(restore_bgm, monkeypatch):
    monkeypatch.setattr(music, "resolve_meting_url", lambda song_id, platform: f"https://cdn/{song_id}.mp3")
    admin = _client_with_role("admin")
    admin.put(
        "/api/music/bgm",
        json={"source": "meting", "song_id": "456", "platform": "netease", "title": "线上歌", "artist": "歌手"},
    )

    data = _client_with_role("visitor").get("/api/music/bgm").json()

    assert data["enabled"] is True
    assert data["source"] == "meting"
    assert data["url"] == "https://cdn/456.mp3"
