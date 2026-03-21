"""通用工具函数"""
import re
from pathlib import Path


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"}
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


def photo_sort_key(path: Path) -> tuple:
    """照片墙排序 key (按文件名中的日期序号)"""
    stem = path.stem
    parts = stem.split("_")
    if len(parts) >= 3 and parts[2].isdigit():
        return (0, int(parts[2]), path.name.lower())
    return (1, 10**9, path.name.lower())
