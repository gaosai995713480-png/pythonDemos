"""TripStar OpenAI 兼容大模型服务。"""
from __future__ import annotations

import json
from typing import Any

import httpx

from ..config import TripStarSettings


class TripStarLLMError(RuntimeError):
    """TripStar 大模型调用失败。"""


def _extract_json_object(text: str) -> dict[str, Any]:
    """从模型输出中提取 JSON 对象，兼容少量 markdown 包裹。"""
    content = (text or "").strip()
    if not content:
        raise TripStarLLMError("大模型返回内容为空")

    if content.startswith("```"):
        lines = content.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        content = "\n".join(lines).strip()

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        start = content.find("{")
        end = content.rfind("}")
        if start < 0 or end <= start:
            raise TripStarLLMError("大模型返回内容不是 JSON 对象")
        try:
            parsed = json.loads(content[start : end + 1])
        except json.JSONDecodeError as exc:
            raise TripStarLLMError("大模型返回 JSON 解析失败") from exc

    if not isinstance(parsed, dict):
        raise TripStarLLMError("大模型返回 JSON 顶层必须是对象")
    return parsed


def _extract_event_stream_content(text: str) -> str:
    """兼容部分 OpenAI 代理始终返回 text/event-stream 的情况。"""
    chunks: list[str] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue
        payload = line.split(":", 1)[1].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            continue
        for choice in event.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else {}
            message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
            content = delta.get("content")
            if content is None:
                content = message.get("content")
            if content:
                chunks.append(str(content))
    return "".join(chunks).strip()


def _extract_chat_content(content_type: str, text: str, data: dict[str, Any]) -> str:
    """从普通 JSON 或 SSE 响应中提取 assistant content。"""
    if "text/event-stream" in (content_type or "").lower():
        content = _extract_event_stream_content(text)
        if not content:
            raise TripStarLLMError("大模型流式响应未包含有效内容")
        return content

    try:
        return str(data["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError) as exc:
        raise TripStarLLMError("大模型接口响应缺少 choices[0].message.content") from exc


class TripStarLLMClient:
    """OpenAI Chat Completions 兼容客户端。

    `base_url` 按 `/v1` 根地址保存；调用时自动追加 `/chat/completions`。
    """

    def __init__(self, settings: TripStarSettings):
        if not settings.has_llm_config:
            raise TripStarLLMError("TripStar 大模型配置不完整")
        self.model = settings.llm_model_id
        self.api_key = settings.llm_api_key
        self.base_url = settings.llm_base_url.rstrip("/")
        self.timeout = settings.llm_timeout

    @property
    def chat_completions_url(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return f"{self.base_url}/chat/completions"

    def chat_json(self, *, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(self.chat_completions_url, headers=headers, json=payload)
                response.raise_for_status()
                content_type = response.headers.get("content-type", "")
                if "text/event-stream" in content_type.lower():
                    data: dict[str, Any] = {}
                else:
                    data = response.json()
        except httpx.HTTPError as exc:
            raise TripStarLLMError(f"大模型接口请求失败：{exc}") from exc
        except ValueError as exc:
            raise TripStarLLMError("大模型接口返回了无法解析的 JSON") from exc

        content = _extract_chat_content(content_type, response.text, data)
        return _extract_json_object(content)
