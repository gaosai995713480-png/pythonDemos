"""
FastAPI 应用入口
"""
import argparse
import logging
import webbrowser

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from .config import settings
from .database import init_tables
from .services.recipe_bootstrap import ensure_howtocook_recipes_seeded

# 路由
from .routers import auth, danmu, timeline, capsule, mood, wish, map, music, weather, photos, config, jukebox, gallery, users, express, ai, ai_skills, ai_conversations, recipes
from .tripstar import router as tripstar_router

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
)
# httpx 的 INFO 日志会输出完整请求 URL；地图/LLM 请求 URL 可能携带 key，
# 因此默认抬高到 WARNING，避免控制台泄露第三方密钥。
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

app = FastAPI(title="xiguasaiLove", docs_url="/docs/api")

# GZip 压缩 (对超过 1KB 的响应进行压缩传输)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(auth.router)
app.include_router(danmu.router)
app.include_router(timeline.router)
app.include_router(capsule.router)
app.include_router(mood.router)
app.include_router(wish.router)
app.include_router(map.router)
app.include_router(music.router)
app.include_router(weather.router)
app.include_router(photos.router)
app.include_router(config.router)
app.include_router(jukebox.router)
app.include_router(gallery.router)
app.include_router(users.router)
app.include_router(express.router)
app.include_router(ai.router)
app.include_router(ai_skills.router)
app.include_router(ai_conversations.router)
app.include_router(recipes.router)
app.include_router(tripstar_router.router)


@app.on_event("startup")
def startup():
    """启动时初始化数据库"""
    try:
        init_tables()
        logger.info("数据库初始化完成")
        seed_result = ensure_howtocook_recipes_seeded(created_by="startup")
        if seed_result.status == "seeded" and seed_result.import_result:
            logger.info(
                "HowToCook 菜谱自动导入完成: total=%s created=%s updated=%s skipped=%s failed=%s",
                seed_result.import_result.total_files,
                seed_result.import_result.created_count,
                seed_result.import_result.updated_count,
                seed_result.import_result.skipped_count,
                seed_result.import_result.failed_count,
            )
        elif seed_result.status == "already_seeded":
            logger.info("HowToCook 菜谱已存在: count=%s", seed_result.existing_count)
        else:
            logger.warning(
                "HowToCook 菜谱自动导入跳过: status=%s error=%s",
                seed_result.status,
                seed_result.error_message,
            )
    except Exception as e:
        logger.warning("数据库初始化失败（部分功能可能不可用）: %s", e)


# 静态文件（assets 等）
app.mount("/assets", StaticFiles(directory=str(settings.web_dir / "assets")), name="assets")


# SPA fallback: 所有非 API/静态资源路由返回 index.html
@app.get("/{path:path}")
async def spa_fallback(request: Request, path: str = ""):
    # 已被 API 路由匹配的不会到这里
    # 有文件扩展名的尝试作为静态文件
    if "." in path.rsplit("/", 1)[-1]:
        file = settings.web_dir / path
        if file.exists():
            return HTMLResponse(content=file.read_bytes(), media_type=_guess_type(path))

    # SPA: 返回 index.html
    index = settings.web_dir / "index.html"
    if index.exists():
        return HTMLResponse(content=index.read_text(encoding="utf-8"))
    return JSONResponse({"error": "index.html not found"}, status_code=404)


def _guess_type(path: str) -> str:
    ext = path.rsplit(".", 1)[-1].lower()
    types = {
        "html": "text/html",
        "css": "text/css",
        "js": "application/javascript",
        "json": "application/json",
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "svg": "image/svg+xml",
        "ico": "image/x-icon",
        "woff": "font/woff",
        "woff2": "font/woff2",
        "webp": "image/webp",
    }
    return types.get(ext, "application/octet-stream")


def main():
    """CLI 入口"""
    import uvicorn

    parser = argparse.ArgumentParser(description="Run love page server (FastAPI)")
    parser.add_argument("--port", type=int, default=8000, help="Server port")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--db-host", default="127.0.0.1", help="MySQL host")
    parser.add_argument("--db-port", type=int, default=3306, help="MySQL port")
    parser.add_argument("--db-user", default="root", help="MySQL user")
    parser.add_argument("--db-password", default="root", help="MySQL password")
    parser.add_argument("--gaode-key", default="", help="Gaode API key")
    args = parser.parse_args()

    # 覆盖配置
    settings.db_host = args.db_host
    settings.db_port = args.db_port
    settings.db_user = args.db_user
    settings.db_password = args.db_password
    if args.gaode_key:
        settings.gaode_key = args.gaode_key

    logger.info("xiguasaiLove (FastAPI) starting at http://%s:%d/", args.host, args.port)
    try:
        webbrowser.open(f"http://{args.host}:{args.port}/", new=1)
    except Exception:
        pass

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
