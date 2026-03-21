"""
main.py 纯函数单元测试 (已迁移到 backend/utils.py)
测试不依赖数据库连接的工具函数
"""
import sys
import os
import pytest

# 将项目根目录加入 sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.utils import validate_identifier, sanitize_upload_filename, is_image_filename, photo_sort_key
from pathlib import Path


class TestValidateIdentifier:
    """validate_identifier 函数测试"""

    def test_normal_identifier(self):
        assert validate_identifier("love_danmu", "test") == "love_danmu"

    def test_alphanumeric(self):
        assert validate_identifier("table123", "test") == "table123"

    def test_uppercase(self):
        assert validate_identifier("MyTable", "test") == "MyTable"

    def test_underscore_only(self):
        assert validate_identifier("___", "test") == "___"

    def test_reject_special_chars(self):
        with pytest.raises(ValueError):
            validate_identifier("table-name", "test")

    def test_reject_spaces(self):
        with pytest.raises(ValueError):
            validate_identifier("table name", "test")

    def test_reject_sql_injection(self):
        with pytest.raises(ValueError):
            validate_identifier("table; DROP TABLE", "test")

    def test_reject_empty(self):
        with pytest.raises(ValueError):
            validate_identifier("", "test")


class TestSanitizeUploadFilename:
    """sanitize_upload_filename 函数测试"""

    def test_normal_filename(self):
        assert sanitize_upload_filename("photo.jpg") == "photo.jpg"

    def test_strip_path(self):
        assert sanitize_upload_filename("C:\\Users\\test\\photo.jpg") == "photo.jpg"

    def test_strip_unix_path(self):
        assert sanitize_upload_filename("/home/user/photo.jpg") == "photo.jpg"

    def test_remove_special_chars(self):
        result = sanitize_upload_filename('photo<>:"|?*.jpg')
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result

    def test_empty_string(self):
        assert sanitize_upload_filename("") == ""

    def test_null_bytes(self):
        result = sanitize_upload_filename("photo\x00.jpg")
        assert "\x00" not in result

    def test_windows_reserved_names(self):
        result = sanitize_upload_filename("con.jpg")
        assert result != "con.jpg"
        assert result.endswith(".jpg")

    def test_trailing_dots(self):
        result = sanitize_upload_filename("photo...")
        assert not result.endswith(".")


class TestIsImageFilename:
    """is_image_filename 函数测试"""

    def test_jpg(self):
        assert is_image_filename("photo.jpg") is True

    def test_jpeg(self):
        assert is_image_filename("photo.jpeg") is True

    def test_png(self):
        assert is_image_filename("photo.png") is True

    def test_webp(self):
        assert is_image_filename("photo.webp") is True

    def test_gif(self):
        assert is_image_filename("photo.gif") is True

    def test_non_image(self):
        assert is_image_filename("file.txt") is False

    def test_no_extension(self):
        assert is_image_filename("photo") is False

    def test_case_insensitive(self):
        assert is_image_filename("photo.JPG") is True


class TestPhotoSortKey:
    """photo_sort_key 函数测试"""

    def test_normal_photo(self):
        key = photo_sort_key(Path("photo_2023_001.jpg"))
        assert key[0] == 0  # 优先级高
        assert key[1] == 1  # 序号

    def test_non_standard_name(self):
        key = photo_sort_key(Path("random_photo.jpg"))
        assert key[0] == 1  # 优先级低

    def test_sorting_order(self):
        paths = [
            Path("photo_2023_003.jpg"),
            Path("photo_2023_001.jpg"),
            Path("random.jpg"),
            Path("photo_2023_002.jpg"),
        ]
        sorted_paths = sorted(paths, key=photo_sort_key)
        assert sorted_paths[0].name == "photo_2023_001.jpg"
        assert sorted_paths[1].name == "photo_2023_002.jpg"
        assert sorted_paths[2].name == "photo_2023_003.jpg"
        assert sorted_paths[3].name == "random.jpg"
