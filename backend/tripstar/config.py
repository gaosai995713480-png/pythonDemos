"""TripStar 模块配置。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from backend.config import settings as app_settings
from backend.database import get_config


def _db_config(name: str) -> str:
    try:
        return get_config(name)
    except Exception:
        return ""


def _config_value(name: str, *env_names: str, default: str = "") -> str:
    db_value = _db_config(name)
    if db_value != "":
        return db_value
    for env_name in (name, *env_names):
        value = os.getenv(env_name)
        if value is not None and value != "":
            return value
    return default


def _env_bool(name: str, default: bool = False) -> bool:
    value = _db_config(name)
    if value == "":
        value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class TripStarSettings:
    """TripStar 独立配置，避免污染当前项目已有配置。"""

    enabled: bool = field(default_factory=lambda: _env_bool("TRIPSTAR_ENABLED", True))
    mock_mode: bool = field(default_factory=lambda: _env_bool("TRIPSTAR_MOCK_MODE", False))

    llm_model_id: str = field(
        default_factory=lambda: _config_value("TRIPSTAR_LLM_MODEL_ID", "LLM_MODEL_ID")
    )
    llm_api_key: str = field(
        default_factory=lambda: _config_value("TRIPSTAR_LLM_API_KEY", "LLM_API_KEY")
    )
    llm_base_url: str = field(
        default_factory=lambda: _config_value("TRIPSTAR_LLM_BASE_URL", "LLM_BASE_URL")
    )
    llm_timeout: int = field(
        default_factory=lambda: int(_config_value("TRIPSTAR_LLM_TIMEOUT", "LLM_TIMEOUT", default="600"))
    )

    amap_web_key: str = field(
        default_factory=lambda: _config_value(
            "TRIPSTAR_AMAP_WEB_KEY",
            "VITE_AMAP_WEB_KEY",
            default=getattr(app_settings, "gaode_key", ""),
        )
    )
    xhs_cookie: str = field(
        default_factory=lambda: _config_value("TRIPSTAR_XHS_COOKIE", "XHS_COOKIE")
    )
    enable_xhs: bool = field(default_factory=lambda: _env_bool("TRIPSTAR_ENABLE_XHS", False))
    google_maps_api_key: str = field(
        default_factory=lambda: _config_value("TRIPSTAR_GOOGLE_MAPS_API_KEY", "GOOGLE_MAPS_API_KEY")
    )
    google_maps_proxy: str = field(
        default_factory=lambda: _config_value("TRIPSTAR_GOOGLE_MAPS_PROXY", "GOOGLE_MAPS_PROXY")
    )
    amap_web_js_key: str = field(
        default_factory=lambda: _config_value("VITE_TRIPSTAR_AMAP_WEB_JS_KEY", "VITE_AMAP_WEB_JS_KEY")
    )
    amap_security_js_code: str = field(
        default_factory=lambda: _config_value("VITE_TRIPSTAR_AMAP_SECURITY_JS_CODE", "VITE_AMAP_SECURITY_JS_CODE")
    )

    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2])

    @property
    def task_dir(self) -> Path:
        return self.base_dir / "data" / "tripstar" / "tasks"

    @property
    def has_llm_config(self) -> bool:
        return bool(self.llm_model_id and self.llm_api_key and self.llm_base_url)

    @property
    def effective_mock_mode(self) -> bool:
        """没有 LLM 配置时强制 mock，避免任务进入无法完成的轮询闭环。"""
        return self.mock_mode or not self.has_llm_config


def get_tripstar_settings() -> TripStarSettings:
    return TripStarSettings()
