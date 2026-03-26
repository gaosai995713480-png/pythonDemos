"""
AI 聊天服务 — 多供应商独立架构
Claude: 通过本地 Claude CLI subprocess 调用
Codex: 通过 httpx 调用 OpenAI Responses API
GLM: 通过 httpx 调用智谱 Chat Completions API
"""
import asyncio
import json
import logging
import shutil
import subprocess
import sys
import threading
from abc import ABC, abstractmethod
from typing import AsyncGenerator

import httpx

from ..database import get_config, set_config

logger = logging.getLogger(__name__)

_TIMEOUT = 120

# ==================== Claude 配置 ====================

CLAUDE_MODEL_KEY = "CLAUDE_MODEL"
_CLAUDE_DEFAULT_MODEL = "claude-sonnet-4-20250514"


def get_claude_config() -> dict:
    return {
        "model": get_config(CLAUDE_MODEL_KEY) or _CLAUDE_DEFAULT_MODEL,
    }


# ==================== Codex 配置 ====================

CODEX_BASE_URL_KEY = "CODEX_BASE_URL"
CODEX_API_KEY_KEY = "CODEX_API_KEY"
CODEX_MODEL_KEY = "CODEX_MODEL"
_CODEX_DEFAULT_MODEL = "gpt-5.4-codex"


def get_codex_config() -> dict:
    return {
        "base_url": get_config(CODEX_BASE_URL_KEY) or "",
        "api_key": get_config(CODEX_API_KEY_KEY) or "",
        "model": get_config(CODEX_MODEL_KEY) or _CODEX_DEFAULT_MODEL,
    }


# ==================== GLM (智谱) 配置 ====================

GLM_BASE_URL_KEY = "GLM_BASE_URL"
GLM_API_KEY_KEY = "GLM_API_KEY"
GLM_MODEL_KEY = "GLM_MODEL"
_GLM_DEFAULT_MODEL = "z-ai/glm-4.7"


def get_glm_config() -> dict:
    return {
        "base_url": get_config(GLM_BASE_URL_KEY) or "https://open.bigmodel.cn/api/paas/v4",
        "api_key": get_config(GLM_API_KEY_KEY) or "",
        "model": get_config(GLM_MODEL_KEY) or _GLM_DEFAULT_MODEL,
    }


# ==================== 抽象基类 ====================

class AiProvider(ABC):
    """AI 供应商抽象接口"""

    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    async def stream_chat(
        self, messages: list[dict]
    ) -> AsyncGenerator[str, None]: ...


# ==================== Claude CLI 实现 ====================

class ClaudeCliProvider(AiProvider):
    """通过本地 Claude CLI 调用（subprocess）"""

    def __init__(self, model: str):
        self.model = model

    def is_available(self) -> bool:
        return shutil.which("claude") is not None

    async def stream_chat(
        self, messages: list[dict]
    ) -> AsyncGenerator[str, None]:
        prompt = self._build_prompt(messages)

        claude_path = shutil.which("claude") or "claude"
        cmd_parts = [claude_path, "-p", "--no-session-persistence"]
        if self.model:
            cmd_parts.extend(["--model", self.model])

        queue: asyncio.Queue[str | None] = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def _run_cli():
            try:
                proc = subprocess.Popen(
                    cmd_parts,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=(sys.platform == "win32"),
                )
                proc.stdin.write(prompt.encode("utf-8"))
                proc.stdin.close()

                while True:
                    chunk = proc.stdout.read(64)
                    if not chunk:
                        break
                    text = chunk.decode("utf-8", errors="replace")
                    loop.call_soon_threadsafe(queue.put_nowait, text)

                proc.wait()
                if proc.returncode != 0:
                    err = proc.stderr.read().decode("utf-8", errors="replace")[:200]
                    if err:
                        logger.warning("Claude CLI stderr: %s", err)
            except FileNotFoundError:
                loop.call_soon_threadsafe(
                    queue.put_nowait, "[错误] 未找到 claude 命令"
                )
            except Exception as e:
                logger.error("Claude CLI 异常: %s", e, exc_info=True)
                loop.call_soon_threadsafe(queue.put_nowait, f"[错误] {e}")
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        thread = threading.Thread(target=_run_cli, daemon=True)
        thread.start()

        try:
            while True:
                chunk = await asyncio.wait_for(queue.get(), timeout=_TIMEOUT)
                if chunk is None:
                    break
                yield chunk
        except asyncio.TimeoutError:
            yield "\n[错误] Claude CLI 响应超时"

    @staticmethod
    def _build_prompt(messages: list[dict]) -> str:
        parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "user":
                parts.append(f"Human: {content}")
            elif role == "assistant":
                parts.append(f"Assistant: {content}")
        return "\n\n".join(parts)


# ==================== Codex 实现 (OpenAI Responses API) ====================

class CodexProvider(AiProvider):
    """Codex — OpenAI Responses API (stream)"""

    def __init__(self, base_url: str, api_key: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model

    def is_available(self) -> bool:
        return bool(self.base_url and self.api_key)

    async def stream_chat(
        self, messages: list[dict]
    ) -> AsyncGenerator[str, None]:
        url = f"{self.base_url}/v1/responses"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        # Responses API 用 input 字段，支持多轮对话
        input_items = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "assistant":
                input_items.append({
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": content}],
                })
            else:
                input_items.append({
                    "role": "user",
                    "content": content,
                })

        body = {
            "model": self.model,
            "stream": True,
            "input": input_items,
            "tools": [{"type": "web_search"}],
        }

        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            async with client.stream(
                "POST", url, headers=headers, json=body
            ) as resp:
                if resp.status_code != 200:
                    error_body = await resp.aread()
                    logger.error("Codex API 错误 [%s]: %s", resp.status_code, error_body[:500])
                    yield f"[错误] API 返回 {resp.status_code}"
                    return

                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        event = json.loads(data_str)
                        # Responses API 流式事件
                        etype = event.get("type", "")
                        if etype == "response.output_text.delta":
                            delta = event.get("delta", "")
                            if delta:
                                yield delta
                    except json.JSONDecodeError:
                        continue


# ==================== GLM (智谱) 实现 ====================

class GlmProvider(AiProvider):
    """智谱 GLM — OpenAI Chat Completions API 兼容 (stream)"""

    def __init__(self, base_url: str, api_key: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model

    def is_available(self) -> bool:
        return bool(self.base_url and self.api_key)

    async def stream_chat(
        self, messages: list[dict]
    ) -> AsyncGenerator[str, None]:
        url = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        chat_messages = []
        for msg in messages:
            chat_messages.append({
                "role": msg.get("role", "user"),
                "content": msg.get("content", ""),
            })

        body = {
            "model": self.model,
            "stream": True,
            "messages": chat_messages,
        }

        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            async with client.stream(
                "POST", url, headers=headers, json=body
            ) as resp:
                if resp.status_code != 200:
                    error_body = await resp.aread()
                    logger.error("GLM API 错误 [%s]: %s", resp.status_code, error_body[:500])
                    yield f"[错误] API 返回 {resp.status_code}"
                    return

                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        event = json.loads(data_str)
                        choices = event.get("choices", [])
                        if choices:
                            delta = choices[0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                yield content
                    except json.JSONDecodeError:
                        continue


# ==================== 工厂方法 ====================

def get_claude_provider() -> ClaudeCliProvider:
    """获取 Claude 供应商实例"""
    cfg = get_claude_config()
    return ClaudeCliProvider(model=cfg["model"])


def get_codex_provider() -> CodexProvider:
    """获取 Codex 供应商实例"""
    cfg = get_codex_config()
    return CodexProvider(
        base_url=cfg["base_url"],
        api_key=cfg["api_key"],
        model=cfg["model"],
    )


def get_glm_provider() -> GlmProvider:
    """获取 GLM 供应商实例"""
    cfg = get_glm_config()
    return GlmProvider(
        base_url=cfg["base_url"],
        api_key=cfg["api_key"],
        model=cfg["model"],
    )


def get_provider(name: str) -> AiProvider:
    """根据名称获取对应的 AI Provider"""
    if name == "claude":
        return get_claude_provider()
    elif name == "codex":
        return get_codex_provider()
    elif name == "glm":
        return get_glm_provider()
    else:
        raise ValueError(f"不支持的 AI 供应商: {name}")
