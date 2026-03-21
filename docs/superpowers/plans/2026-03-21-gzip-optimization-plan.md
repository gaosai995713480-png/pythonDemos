# GZip 压缩性能优化 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 通过引入 FastAPI 原生 GZip 中间件，开启全局静态文件与响应数据的自动压缩，大幅缩减前端网页初次加载与调用接口传输体积。

**Architecture:** 直接在 `backend/main.py` 安装 `GZipMiddleware` 拦截全局响应，配置门槛值限制其只对 >1KB 数据进行处理。

**Tech Stack:** FastAPI, Python, Pytest

---

### Task 1: 引入并配置 GZip Middleware

**Files:**
- Create: `tests/test_gzip.py`
- Modify: `backend/main.py`

- [ ] **Step 1: Write the failing test**

创建 `tests/test_gzip.py`，向一个返回较大数据量的接口获取报文，测试返回头部中是否有 `content-encoding: gzip`。
这里我们利用请求 `/api/weather/locate` 或者直出较大静态文件的接口进行测试（需伪造大的返回体或请求头携带 `Accept-Encoding: gzip`）。

```python
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_gzip_compression_enabled():
    # 发送允许接收 Gzip 的请求，触发路由让其返回超过 1000 字节的响应（如大文本）
    # 由于难以确保某些接口稳定超过 1000 字节，我们添加一个临时的测使用大型路由或者利用已有接口
    # 为了测试目的，可以请求一个大字符串
    @app.get("/test_large_response")
    def large_response():
        return {"data": "A" * 2000}
        
    response = client.get("/test_large_response", headers={"Accept-Encoding": "gzip"})
    
    # 验证响应码与压缩标志
    assert response.status_code == 200
    assert response.headers.get("content-encoding") == "gzip"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_gzip.py -v`
Expected: FAIL (因为目前还没有 GZip 中间件拦截压缩响应)

- [ ] **Step 3: Write minimal implementation**

修改 `backend/main.py` 文件，在其顶部增加导包和设置逻辑：
```python
from fastapi.middleware.gzip import GZipMiddleware

...

app = FastAPI(title="Love Page", docs_url="/docs/api")

# 添加 Gzip 压缩，配置大于 1KB 时执行压缩
app.add_middleware(GZipMiddleware, minimum_size=1000)

# CORS
...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_gzip.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/main.py tests/test_gzip.py
git commit -m "perf(config): 全局启用 GZip 响应压缩提升网络加载速度"
```
