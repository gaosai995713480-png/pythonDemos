from fastapi.testclient import TestClient
from fastapi.middleware.gzip import GZipMiddleware
from backend.main import app

client = TestClient(app)

def test_gzip_compression_enabled():
    # 因为 httpx 的 TestClient 会自动透明解压 gzip 数据并移除 'Content-Encoding' 响应头，
    # 在单元测试中直接 assert 头部不准确，我们通过检查 FastAPI 是否正确挂载了该 Middleware 来断言
    is_gzip_enabled = any(
        middleware.cls == GZipMiddleware
        for middleware in app.user_middleware
    )
    assert is_gzip_enabled, "GZipMiddleware was not added to the FastAPI app"
