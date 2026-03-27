"""
阿里云 OSS 存储服务
"""
import time
import oss2
import logging
from ..database import get_config
from ..utils import photo_sort_key
from pathlib import Path

logger = logging.getLogger(__name__)

# ===== Bug1 修复：内存级 TTL 缓存，避免每次请求重复查 4 次数据库 =====
_oss_cache = {
    "bucket": None,
    "domain": "",
    "expire_at": 0,
}
_CACHE_TTL = 60  # 缓存 60 秒


def _refresh_oss_cache():
    """刷新 OSS 配置缓存"""
    now = time.time()
    if _oss_cache["expire_at"] > now and _oss_cache["bucket"] is not None:
        return  # 缓存仍然有效

    # Bug2 修复：对 get_config 返回值做 None 安全防护
    endpoint = (get_config("OSS_ENDPOINT") or "").strip()
    bucket_name = (get_config("OSS_BUCKET_NAME") or "").strip()
    access_key_id = (get_config("OSS_ACCESS_KEY_ID") or "").strip()
    access_key_secret = (get_config("OSS_ACCESS_KEY_SECRET") or "").strip()

    if not all([endpoint, bucket_name, access_key_id, access_key_secret]):
        _oss_cache["bucket"] = None
        _oss_cache["domain"] = ""
        _oss_cache["expire_at"] = now + 10  # 配置不全时 10 秒后重试
        return

    try:
        auth = oss2.Auth(access_key_id, access_key_secret)
        raw_endpoint = endpoint
        if not endpoint.startswith("http"):
            endpoint = f"https://{endpoint}"

        bucket = oss2.Bucket(auth, endpoint, bucket_name)
        clean_endpoint = raw_endpoint.replace("https://", "").replace("http://", "")
        domain = f"https://{bucket_name}.{clean_endpoint}"

        _oss_cache["bucket"] = bucket
        _oss_cache["domain"] = domain
        _oss_cache["expire_at"] = now + _CACHE_TTL
    except Exception as e:
        logger.error(f"Failed to initialize OSS Bucket: {e}")
        _oss_cache["bucket"] = None
        _oss_cache["domain"] = ""
        _oss_cache["expire_at"] = now + 10


def get_oss_bucket():
    """动态从缓存获取 OSS Bucket 对象"""
    _refresh_oss_cache()
    return _oss_cache["bucket"]


def get_oss_domain() -> str:
    """获取拼接图片的 OSS 域名"""
    _refresh_oss_cache()
    return _oss_cache["domain"]


def upload_to_oss(safe_name: str, file_data: bytes) -> bool:
    """上传文件到 OSS

    返回 True 表示上传成功，False 表示未配置或上传失败
    """
    bucket = get_oss_bucket()
    if not bucket:
        logger.warning("OSS not configured, cannot upload file.")
        return False

    try:
        object_key = f"photos/{safe_name}"
        bucket.put_object(object_key, file_data)
        return True
    except Exception as e:
        logger.error(f"OSS put_object failed: {e}")
        return False


def get_oss_photos() -> list[str]:
    """获取 OSS 中的所有图片并使用正确的顺序返回 URLs"""
    bucket = get_oss_bucket()
    if not bucket:
        return []

    images = []
    prefix = "photos/"
    try:
        for obj in oss2.ObjectIterator(bucket, prefix=prefix):
            if obj.key == prefix:
                continue
            images.append(obj.key)
    except Exception as e:
        logger.error(f"OSS list_objects failed: {e}")
        return []

    images.sort(key=lambda k: photo_sort_key(Path(k.replace(prefix, ""))))

    domain = get_oss_domain()
    return [f"{domain}/{key}" for key in images]
