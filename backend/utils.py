"""通用工具函数"""
import re
import time
from pathlib import Path


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"}
# 只保留 iOS/Safari 也能解码的格式：flac/ogg 在苹果设备上放不出来，提前拒绝好过传完才发现
AUDIO_EXTENSIONS = {".mp3", ".m4a", ".aac", ".wav"}
AUDIO_MIME_TYPES = {
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".aac": "audio/aac",
    ".wav": "audio/wav",
}
WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def validate_identifier(name: str, desc: str = "Identifier") -> str:
    """验证表名或库名只包含字母、数字和下划线"""
    if not name:
        raise ValueError(f"{desc} cannot be empty.")
    if not re.match(r"^[A-Za-z0-9_]+$", name):
        raise ValueError(f"{desc} contains invalid characters.")
    return name


def is_image_filename(name: str) -> bool:
    """判断是否为支持的图片文件名"""
    return Path(name).suffix.lower() in IMAGE_EXTENSIONS


def is_audio_filename(name: str) -> bool:
    """判断是否为支持的音频文件名"""
    return Path(name).suffix.lower() in AUDIO_EXTENSIONS


def audio_mime_type(name: str) -> str:
    """根据音频文件名推断 Content-Type"""
    return AUDIO_MIME_TYPES.get(Path(name).suffix.lower(), "application/octet-stream")


def sanitize_upload_filename(raw_name: str) -> str:
    """清理上传文件名，防止路径穿越和特殊字符"""
    name = (raw_name or "").strip().replace("\x00", "")
    if not name:
        return ""
    name = name.replace("\\", "/").split("/")[-1].strip()
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).rstrip(" .")
    if not name:
        return ""
    if Path(name).stem.lower() in WINDOWS_RESERVED_NAMES:
        name = f"_{name}"
    return name


def aligned_expires() -> int:
    """计算到下一个整点小时的剩余秒数，保证同一小时内签名 URL 完全一致，命中浏览器缓存"""
    now = int(time.time())
    next_hour = (now // 3600 + 1) * 3600
    return max(next_hour - now, 300)  # 最少保证 5 分钟有效


def photo_sort_key(path: Path) -> tuple:
    """照片墙排序 key (按文件名中的日期序号)"""
    stem = path.stem
    parts = stem.split("_")
    if len(parts) >= 3 and parts[2].isdigit():
        return (0, int(parts[2]), path.name.lower())
    return (1, 10**9, path.name.lower())
