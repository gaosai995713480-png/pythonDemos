"""
Agent 循环引擎

实现 Think → Act → Observe 循环，支持 LLM 多轮工具调用。
通过 SSE 事件通知前端工具调用过程。
"""
import json
import logging
from typing import AsyncGenerator

import httpx

from ..database import get_config
from .agent_tools import (
    get_tools_for_openai,
    get_tools_for_anthropic,
    execute_tool,
)

logger = logging.getLogger(__name__)

_TIMEOUT = 120


def _get_max_rounds() -> int:
    """获取最大工具调用轮数"""
    try:
        return int(get_config("AGENT_MAX_TOOL_ROUNDS") or 5)
    except (ValueError, TypeError):
        return 5


def _show_tool_process() -> bool:
    """是否展示工具调用过程"""
    val = get_config("AGENT_SHOW_TOOL_PROCESS")
    return val != "false"


# ==================== Codex (OpenAI) Agent ====================


async def codex_agent_loop(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict],
) -> AsyncGenerator[str, None]:
    """Codex Agent 循环 — OpenAI Chat Completions + tools"""
    tools = get_tools_for_openai()
    max_rounds = _get_max_rounds()
    show_process = _show_tool_process()
    url = f"{base_url.rstrip('/')}/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    working_messages = list(messages)

    for round_idx in range(max_rounds):
        body = {
            "model": model,
            "messages": working_messages,
            "tools": tools,
            "stream": True,
        }

        # 收集本轮完整响应
        full_content = ""
        tool_calls_acc: dict[int, dict] = {}  # index -> {id, name, arguments}

        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            async with client.stream("POST", url, headers=headers, json=body) as resp:
                if resp.status_code != 200:
                    error_body = await resp.aread()
                    logger.error("Codex Agent API 错误 [%s]: %s", resp.status_code, error_body[:500])
                    yield json.dumps({"type": "error", "content": f"API 返回 {resp.status_code}"})
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
                        if not choices:
                            continue
                        delta = choices[0].get("delta", {})

                        # 文本内容
                        content = delta.get("content")
                        if content:
                            full_content += content
                            yield json.dumps(content)

                        # 工具调用
                        tc_list = delta.get("tool_calls", [])
                        for tc in tc_list:
                            idx = tc.get("index", 0)
                            if idx not in tool_calls_acc:
                                tool_calls_acc[idx] = {
                                    "id": tc.get("id", ""),
                                    "name": "",
                                    "arguments": "",
                                }
                            if tc.get("id"):
                                tool_calls_acc[idx]["id"] = tc["id"]
                            func = tc.get("function", {})
                            if func.get("name"):
                                tool_calls_acc[idx]["name"] = func["name"]
                            if func.get("arguments"):
                                tool_calls_acc[idx]["arguments"] += func["arguments"]

                    except json.JSONDecodeError:
                        continue

        # 判断：有工具调用？
        if not tool_calls_acc:
            # 纯文本回复，结束
            return

        # 将 assistant 消息（含 tool_calls）加入历史
        assistant_msg = {"role": "assistant", "content": full_content or None}
        assistant_msg["tool_calls"] = [
            {
                "id": tc["id"],
                "type": "function",
                "function": {
                    "name": tc["name"],
                    "arguments": tc["arguments"],
                },
            }
            for tc in tool_calls_acc.values()
        ]
        working_messages.append(assistant_msg)

        # 逐个执行工具
        for tc in tool_calls_acc.values():
            tool_name = tc["name"]
            try:
                args = json.loads(tc["arguments"])
            except json.JSONDecodeError:
                args = {}

            # 通知前端：工具调用中
            if show_process:
                yield json.dumps({
                    "type": "tool_call",
                    "name": tool_name,
                    "args": args,
                })

            # 执行
            result = await execute_tool(tool_name, args)

            # 通知前端：工具结果
            if show_process:
                yield json.dumps({
                    "type": "tool_result",
                    "name": tool_name,
                    "result": result,
                })

            # 加入消息历史
            working_messages.append({
                "role": "tool",
                "tool_call_id": tc["id"],
                "content": result,
            })

    # 超过最大轮数：不带 tools 再请求一次，强制模型基于已有工具结果收尾
    working_messages.append({
        "role": "system",
        "content": "你已达到工具调用次数上限，请基于已获取的信息直接回答用户问题，不要再调用工具。"
    })
    yield json.dumps("[提示] 已达到最大工具调用轮数，正在生成总结...")

    summary_body = {"model": model, "messages": working_messages, "stream": True}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            async with client.stream("POST", url, headers=headers, json=summary_body) as resp:
                if resp.status_code != 200:
                    yield json.dumps(f"\n\n抱歉，无法生成总结（HTTP {resp.status_code}）")
                    return
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        event = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue
                    choices = event.get("choices", [])
                    if not choices:
                        continue
                    content = (choices[0].get("delta") or {}).get("content")
                    if content:
                        yield json.dumps(content)
    except Exception as e:
        logger.error("超轮数总结生成失败: %s", e, exc_info=True)
        yield json.dumps(f"\n\n总结生成失败：{e}")


# ==================== Claude (Anthropic) Agent ====================


async def claude_agent_loop(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict],
) -> AsyncGenerator[str, None]:
    """Claude Agent 循环 — Anthropic Messages API + tools"""
    tools = get_tools_for_anthropic()
    max_rounds = _get_max_rounds()
    show_process = _show_tool_process()
    url = f"{base_url.rstrip('/')}/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }

    # 分离 system 消息
    system_text = ""
    chat_messages = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system":
            system_text = content
        else:
            chat_messages.append({"role": role, "content": content})

    for round_idx in range(max_rounds):
        body = {
            "model": model,
            "max_tokens": 4096,
            "stream": True,
            "messages": chat_messages,
            "tools": tools,
        }
        if system_text:
            body["system"] = system_text

        # 收集本轮完整响应
        full_text = ""
        tool_uses: list[dict] = []  # {id, name, input_json_str}
        current_tool_id = ""
        current_tool_name = ""
        current_tool_input = ""

        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            async with client.stream("POST", url, headers=headers, json=body) as resp:
                if resp.status_code != 200:
                    error_body = await resp.aread()
                    logger.error("Claude Agent API 错误 [%s]: %s", resp.status_code, error_body[:500])
                    yield json.dumps({"type": "error", "content": f"API 返回 {resp.status_code}"})
                    return

                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    try:
                        event = json.loads(data_str)
                        etype = event.get("type", "")

                        if etype == "content_block_start":
                            block = event.get("content_block", {})
                            if block.get("type") == "tool_use":
                                current_tool_id = block.get("id", "")
                                current_tool_name = block.get("name", "")
                                current_tool_input = ""

                        elif etype == "content_block_delta":
                            delta = event.get("delta", {})
                            if delta.get("type") == "text_delta":
                                text = delta.get("text", "")
                                if text:
                                    full_text += text
                                    yield json.dumps(text)
                            elif delta.get("type") == "input_json_delta":
                                current_tool_input += delta.get("partial_json", "")

                        elif etype == "content_block_stop":
                            if current_tool_name:
                                tool_uses.append({
                                    "id": current_tool_id,
                                    "name": current_tool_name,
                                    "input_json": current_tool_input,
                                })
                                current_tool_name = ""

                    except json.JSONDecodeError:
                        continue

        # 判断：有工具调用？
        if not tool_uses:
            return

        # 构建 assistant 消息
        assistant_content = []
        if full_text:
            assistant_content.append({"type": "text", "text": full_text})
        for tu in tool_uses:
            try:
                input_data = json.loads(tu["input_json"]) if tu["input_json"] else {}
            except json.JSONDecodeError:
                input_data = {}
            assistant_content.append({
                "type": "tool_use",
                "id": tu["id"],
                "name": tu["name"],
                "input": input_data,
            })
        chat_messages.append({"role": "assistant", "content": assistant_content})

        # 执行工具并构建 tool_result
        tool_results = []
        for tu in tool_uses:
            try:
                args = json.loads(tu["input_json"]) if tu["input_json"] else {}
            except json.JSONDecodeError:
                args = {}

            if show_process:
                yield json.dumps({
                    "type": "tool_call",
                    "name": tu["name"],
                    "args": args,
                })

            result = await execute_tool(tu["name"], args)

            if show_process:
                yield json.dumps({
                    "type": "tool_result",
                    "name": tu["name"],
                    "result": result,
                })

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tu["id"],
                "content": result,
            })

        chat_messages.append({"role": "user", "content": tool_results})

    # 超过最大轮数：不带 tools 再请求一次，强制模型基于已有工具结果收尾
    yield json.dumps("[提示] 已达到最大工具调用轮数，正在生成总结...")

    summary_body = {
        "model": model,
        "max_tokens": 4096,
        "stream": True,
        "messages": chat_messages + [{
            "role": "user",
            "content": "你已达到工具调用次数上限，请基于以上工具结果直接回答用户的原始问题，不要再调用工具。"
        }],
    }
    if system_text:
        summary_body["system"] = system_text
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            async with client.stream("POST", url, headers=headers, json=summary_body) as resp:
                if resp.status_code != 200:
                    yield json.dumps(f"\n\n抱歉，无法生成总结（HTTP {resp.status_code}）")
                    return
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    try:
                        event = json.loads(line[6:])
                    except json.JSONDecodeError:
                        continue
                    if event.get("type") == "content_block_delta":
                        delta = event.get("delta", {})
                        if delta.get("type") == "text_delta":
                            text = delta.get("text", "")
                            if text:
                                yield json.dumps(text)
    except Exception as e:
        logger.error("超轮数总结生成失败: %s", e, exc_info=True)
        yield json.dumps(f"\n\n总结生成失败：{e}")
