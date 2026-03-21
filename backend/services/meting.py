"""
Meting CLI 调用服务
"""
import json
import logging
import os
import subprocess
from pathlib import Path

from dotenv import load_dotenv

# 加载项目根目录的 .env（Cookie 等配置），作为 fallback
_project_root = Path(__file__).resolve().parent.parent.parent
load_dotenv(_project_root / ".env")

logger = logging.getLogger(__name__)

METING_CLI_PATH = str(_project_root / "meting" / "meting-cli.mjs")
METING_PLATFORMS = {"netease", "tencent", "kugou", "baidu", "kuwo"}


def call_meting(command: str, **kwargs) -> dict:
    """调用 Meting CLI 获取音乐数据。优先使用数据库中的 Cookie。"""
    cmd = ["node", METING_CLI_PATH, command]
    for k, v in kwargs.items():
        cmd.extend([f"--{k}", str(v)])

    # 构建子进程环境变量：.env（已在 os.environ）+ 数据库 Cookie 覆盖
    env = os.environ.copy()
    try:
        from ..database import get_all_cookies
        db_cookies = get_all_cookies()
        env.update(db_cookies)
    except Exception:
        pass  # 数据库不可用时，降级使用 .env 中的值

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15,
            encoding="utf-8", env=env,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except Exception as e:
        logger.warning("call_meting error: %s", e)
    return {}
