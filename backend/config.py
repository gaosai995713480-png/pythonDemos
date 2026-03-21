"""
应用配置管理 - 对应原 argparse 参数
"""
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class Settings:
    host: str = "127.0.0.1"
    port: int = 0

    # MySQL
    db_host: str = "127.0.0.1"
    db_port: int = 3306
    db_user: str = "root"
    db_password: str = "root"
    db_name: str = "love_page"

    # 表名
    danmu_table: str = "love_danmu"
    auth_table: str = "love_auth"
    timeline_table: str = "love_timeline"
    capsule_table: str = "love_capsule"
    mood_table: str = "love_mood"
    wish_table: str = "love_wish"
    map_table: str = "love_map"
    music_table: str = "love_music"

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
