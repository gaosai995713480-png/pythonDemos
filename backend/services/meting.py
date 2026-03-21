"""
Meting CLI 调用服务
"""
import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

METING_CLI_PATH = str(Path(__file__).resolve().parent.parent.parent / "meting" / "meting-cli.mjs")
METING_PLATFORMS = {"netease", "tencent", "kugou", "baidu", "kuwo"}


def call_meting(command: str, **kwargs) -> dict:
    """调用 Meting CLI 获取音乐数据。"""
    cmd = ["node", METING_CLI_PATH, command]
    for k, v in kwargs.items():
        cmd.extend([f"--{k}", str(v)])
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, encoding="utf-8"
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except Exception as e:
        logger.warning("call_meting error: %s", e)
    return {}
