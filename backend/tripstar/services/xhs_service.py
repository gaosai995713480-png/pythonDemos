"""TripStar 小红书服务适配器。"""
from __future__ import annotations

import json
import random
import subprocess
from pathlib import Path
from typing import Any

import httpx


class XhsServiceError(RuntimeError):
    """小红书服务调用失败。"""


class XhsCookieExpiredError(XhsServiceError):
    """小红书 Cookie 失效或被风控。"""


XHS_BASE_URL = "https://edith.xiaohongshu.com"
XHS_SEARCH_API = "/api/sns/web/v1/search/notes"


def normalize_xhs_cookie(cookie: str) -> str:
    """兼容请求头字符串、`Cookie: xxx` 和浏览器 JSON Cookie 列表。"""
    normalized = (cookie or "").strip()
    if not normalized:
        return ""

    if normalized.lower().startswith("cookie:"):
        normalized = normalized.split(":", 1)[1].strip()

    if len(normalized) >= 2 and normalized[0] == normalized[-1] and normalized[0] in {"'", '"'}:
        normalized = normalized[1:-1].strip()

    cookie_items = None
    if normalized.startswith("[") and normalized.endswith("]"):
        try:
            cookie_items = json.loads(normalized)
        except json.JSONDecodeError:
            cookie_items = None
    elif normalized.startswith("{") and '"name"' in normalized and '"value"' in normalized:
        try:
            cookie_items = json.loads(f"[{normalized}]")
        except json.JSONDecodeError:
            cookie_items = None

    if isinstance(cookie_items, list):
        pairs: list[str] = []
        for item in cookie_items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            value = str(item.get("value", "")).strip()
            if name:
                pairs.append(f"{name}={value}")
        if pairs:
            return "; ".join(pairs)

    return normalized


def _cookie_dict(cookie: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in cookie.split(";"):
        if "=" not in item:
            continue
        name, value = item.split("=", 1)
        result[name.strip()] = value.strip()
    return result


def _random_trace_id(length: int = 16) -> str:
    alphabet = "abcdef0123456789"
    return "".join(random.choice(alphabet) for _ in range(length))


def _count_text(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("万"):
            try:
                return int(float(text[:-1]) * 10000)
            except ValueError:
                return 0
        try:
            return int(float(text))
        except ValueError:
            return 0
    return 0


def _image_url(image: dict[str, Any]) -> str:
    info_list = image.get("info_list")
    if isinstance(info_list, list):
        for item in info_list:
            if isinstance(item, dict) and item.get("url"):
                return item["url"]
    return (
        image.get("url_default")
        or image.get("url_pre")
        or image.get("url")
        or image.get("trace_id")
        or ""
    )


class XhsService:
    """封装小红书搜索能力。

    真实接口优先使用迁移自 TripStar 的本地 JS 签名文件生成 `x-s/x-t/x-s-common`，
    避免把 Cookie 暴露给前端。签名或远端接口失败时向调用方返回明确错误。
    """

    def __init__(self, cookie: str, timeout: float = 12.0):
        self.cookie = normalize_xhs_cookie(cookie)
        self.timeout = timeout

    @property
    def cookie_length(self) -> int:
        return len(self.cookie)

    def search_notes(self, keyword: str, limit: int = 6) -> list[dict[str, Any]]:
        keyword = keyword.strip()
        if not keyword:
            raise XhsServiceError("小红书搜索关键词不能为空")
        if not self.cookie:
            raise XhsServiceError("TripStar 小红书 Cookie 未配置")

        safe_limit = max(1, min(int(limit or 6), 20))
        body = self._search_body(keyword, safe_limit)
        headers = self._headers(XHS_SEARCH_API, body, "POST")
        try:
            response = httpx.post(
                f"{XHS_BASE_URL}{XHS_SEARCH_API}",
                headers=headers,
                content=json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPError as exc:
            raise XhsServiceError(f"小红书接口请求失败：{exc}") from exc
        except ValueError as exc:
            raise XhsServiceError("小红书接口返回了无法解析的 JSON") from exc

        if not payload.get("success", False):
            code = payload.get("code", "")
            message = payload.get("msg") or payload.get("message") or "未知错误"
            if str(code) == "300011" or "异常" in str(message) or "登录" in str(message):
                raise XhsCookieExpiredError(f"小红书 Cookie 可能失效或被风控：{message}")
            raise XhsServiceError(f"小红书搜索失败：{message}")

        items = payload.get("data", {}).get("items", [])
        return self._normalize_items(items, safe_limit)

    def _search_body(self, keyword: str, limit: int) -> dict[str, Any]:
        return {
            "keyword": keyword,
            "page": 1,
            "page_size": limit,
            "search_id": _random_trace_id(21),
            "sort": "general",
            "note_type": 0,
            "ext_flags": [],
            "filters": [
                {"tags": ["general"], "type": "sort_type"},
                {"tags": ["不限"], "type": "filter_note_type"},
                {"tags": ["不限"], "type": "filter_note_time"},
                {"tags": ["不限"], "type": "filter_note_range"},
                {"tags": ["不限"], "type": "filter_pos_distance"},
            ],
            "geo": "",
            "image_formats": ["jpg", "webp", "avif"],
        }

    def _headers(self, api: str, body: dict[str, Any], method: str) -> dict[str, str]:
        headers = {
            "accept": "application/json, text/plain, */*",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
            "cache-control": "no-cache",
            "content-type": "application/json;charset=UTF-8",
            "cookie": self.cookie,
            "origin": "https://www.xiaohongshu.com",
            "pragma": "no-cache",
            "referer": "https://www.xiaohongshu.com/",
            "sec-ch-ua": '"Chromium";v="121", "Not A(Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
            ),
            "x-b3-traceid": _random_trace_id(16),
            "x-s": "",
            "x-t": "",
            "x-s-common": "",
        }
        headers.update(self._signature_headers(api, body, method))
        return headers

    def _signature_headers(self, api: str, body: dict[str, Any], method: str) -> dict[str, str]:
        cookie_values = _cookie_dict(self.cookie)
        a1 = cookie_values.get("a1", "")
        if not a1:
            raise XhsServiceError("小红书 Cookie 缺少 a1 字段，请重新复制完整 Cookie")

        # 验证 a1 格式，防止注入
        if not a1.replace("-", "").replace("_", "").isalnum():
            raise XhsServiceError("小红书 Cookie a1 字段格式非法")

        sign_file = Path(__file__).resolve().parent / "xhs_sign" / "xhs_xs_xsc_56.js"
        if not sign_file.exists():
            raise XhsServiceError("小红书签名文件缺失，无法调用真实搜索接口")

        node_script = f"""
const signer = require({json.dumps(str(sign_file))});
const chunks = [];
process.stdin.on('data', chunk => chunks.push(chunk));
process.stdin.on('end', () => {{
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const result = signer.get_request_headers_params(input.api, input.body, input.a1, input.method);
  process.stdout.write(JSON.stringify(result));
}});
"""
        payload = json.dumps(
            {"api": api, "body": body, "a1": a1, "method": method},
            ensure_ascii=False,
            separators=(",", ":"),
        )

        try:
            completed = subprocess.run(
                ["node", "-e", node_script],
                input=payload,
                text=True,
                capture_output=True,
                timeout=8,
                check=True,
                encoding="utf-8",
            )
            output = completed.stdout.strip()
            json_start = output.find("{")
            if json_start > 0:
                output = output[json_start:]
            signed = json.loads(output)
        except FileNotFoundError as exc:
            raise XhsServiceError("服务器未安装 Node.js，无法生成小红书签名") from exc
        except (subprocess.SubprocessError, json.JSONDecodeError, KeyError) as exc:
            raise XhsServiceError("小红书签名生成失败") from exc

        return {
            "x-s": str(signed.get("xs", "")),
            "x-t": str(signed.get("xt", "")),
            "x-s-common": str(signed.get("xs_common", "")),
        }

    def _normalize_items(self, items: list[Any], limit: int) -> list[dict[str, Any]]:
        notes: list[dict[str, Any]] = []
        for raw in items:
            if not isinstance(raw, dict):
                continue
            note_card = raw.get("note_card") if isinstance(raw.get("note_card"), dict) else raw
            note_id = raw.get("id") or note_card.get("id") or note_card.get("note_id") or ""
            title = note_card.get("display_title") or note_card.get("title") or "小红书笔记"
            desc = note_card.get("desc") or note_card.get("description") or ""
            user = note_card.get("user") or note_card.get("user_info") or raw.get("user") or {}
            interact = note_card.get("interact_info") or {}
            image_list = note_card.get("image_list") or note_card.get("images_list") or []
            cover_url = ""
            if isinstance(image_list, list) and image_list:
                first = image_list[0]
                if isinstance(first, dict):
                    cover_url = _image_url(first)

            notes.append(
                {
                    "id": note_id,
                    "title": title,
                    "desc": desc,
                    "liked_count": _count_text(
                        interact.get("liked_count")
                        or interact.get("likes")
                        or note_card.get("liked_count")
                        or raw.get("liked_count")
                    ),
                    "collected_count": _count_text(
                        interact.get("collected_count")
                        or interact.get("collect_count")
                        or raw.get("collected_count")
                    ),
                    "comment_count": _count_text(
                        interact.get("comment_count") or raw.get("comment_count")
                    ),
                    "cover_url": cover_url,
                    "note_url": f"https://www.xiaohongshu.com/explore/{note_id}" if note_id else "",
                    "xsec_token": raw.get("xsec_token") or "",
                    "author": {
                        "nickname": user.get("nickname") or user.get("nick_name") or "小红书用户",
                        "avatar": user.get("avatar") or user.get("image") or "",
                        "user_id": user.get("user_id") or user.get("id") or "",
                    },
                }
            )
            if len(notes) >= limit:
                break
        return notes
