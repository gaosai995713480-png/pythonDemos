"""
应用配置管理 - 从环境变量加载
"""
import os
from pathlib import Path
from dataclasses import dataclass, field
from dotenv import load_dotenv

# 加载 .env 文件（如果存在）
load_dotenv()

@dataclass
class Settings:
    host: str = os.getenv("LOVE_HOST", "127.0.0.1")
    port: int = int(os.getenv("LOVE_PORT", "0"))

    # MySQL
    db_host: str = os.getenv("DB_HOST", "127.0.0.1")
    db_port: int = int(os.getenv("DB_PORT", "3306"))
    db_user: str = os.getenv("DB_USER", "root")
    db_password: str = os.getenv("DB_PASSWORD", "root")
    db_name: str = os.getenv("DB_NAME", "love_page")

    # 表名
    danmu_table: str = os.getenv("TABLE_DANMU", "love_danmu")
    auth_table: str = os.getenv("TABLE_AUTH", "love_auth")
    timeline_table: str = os.getenv("TABLE_TIMELINE", "love_timeline")
    capsule_table: str = os.getenv("TABLE_CAPSULE", "love_capsule")
    mood_table: str = os.getenv("TABLE_MOOD", "love_mood")
    wish_table: str = os.getenv("TABLE_WISH", "love_wish")
    map_table: str = os.getenv("TABLE_MAP", "love_map")
    music_table: str = os.getenv("TABLE_MUSIC", "love_music")

    # 弹幕
    danmu_limit: int = 50
    danmu_maxlen: int = 40

    # 默认密码
    default_password: str = "20231026"

    # 高德 API
    gaode_key: str = "c34bbce1d41994a5c7819ea44a0a004f"

    # 路径
    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)

    @property
    def web_dir(self) -> Path:
        return self.base_dir / "docs"

    @property
    def photos_dir(self) -> Path:
        return self.web_dir / "photos"


settings = Settings()
