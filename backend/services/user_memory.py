"""
用户长期记忆服务

功能：
1. 事实存储/检索/删除
2. 记忆自动注入（拼接到 system prompt）
3. 对话后异步事实提取（通过 LLM）
"""
import json
import logging
from typing import Optional

from ..database import get_db, get_config

logger = logging.getLogger(__name__)

# 最大注入记忆条数
_MAX_INJECT_FACTS = 50


def save_fact(username: str, fact_content: str, category: str = "general", source: str = "auto") -> int:
    """保存一条用户事实，返回 id。如果内容重复则跳过。"""
    fact_content = fact_content.strip()
    if not fact_content:
        return 0

    with get_db() as conn:
        with conn.cursor() as cursor:
            # 去重：相同用户相同内容不重复存
            cursor.execute(
                "SELECT id FROM user_facts WHERE username = %s AND fact_content = %s",
                (username, fact_content),
            )
            existing = cursor.fetchone()
            if existing:
                return existing[0]

            cursor.execute(
                "INSERT INTO user_facts (username, fact_content, category, source) VALUES (%s, %s, %s, %s)",
                (username, fact_content, category, source),
            )
            row_id = cursor.lastrowid
        conn.commit()
    logger.info("保存用户事实 [%s]: %s (category=%s, source=%s)", username, fact_content[:60], category, source)
    return row_id


def get_user_facts(username: str, limit: int = _MAX_INJECT_FACTS) -> list[dict]:
    """获取用户所有事实"""
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, fact_content, category, source, created_at FROM user_facts "
                "WHERE username = %s ORDER BY created_at DESC LIMIT %s",
                (username, limit),
            )
            rows = cursor.fetchall()
    return [
        {
            "id": r[0],
            "content": r[1],
            "category": r[2],
            "source": r[3],
            "created_at": r[4].isoformat() if r[4] else None,
        }
        for r in rows
    ]


def delete_fact(username: str, fact_id: int) -> bool:
    """删除一条事实"""
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM user_facts WHERE id = %s AND username = %s",
                (fact_id, username),
            )
            affected = cursor.rowcount
        conn.commit()
    return affected > 0


def build_memory_prompt(username: str) -> str:
    """构建记忆注入的 system prompt 片段"""
    facts = get_user_facts(username)
    if not facts:
        return ""

    lines = ["[长期记忆] 以下是关于用户的已知信息，请在回复时自然地参考这些记忆："]
    for f in facts:
        category_label = {
            "general": "📝",
            "date": "📅",
            "preference": "❤️",
            "person": "👤",
        }.get(f["category"], "📝")
        lines.append(f"- {category_label} {f['content']}")

    return "\n".join(lines)


async def extract_facts_from_conversation(
    username: str,
    user_message: str,
    ai_response: str,
    provider_name: str = "codex",
) -> list[str]:
    """
    对话结束后，异步调用 LLM 从对话中提取用户事实。
    使用轻量级提示，不走 Agent Loop。
    """
    import httpx
    from ..services.ai_chat import get_codex_config, get_claude_config

    extraction_prompt = f"""请从以下对话中提取关于用户的关键个人事实信息。

只提取明确的事实，例如：
- 重要日期（生日、纪念日、入职日等）
- 个人偏好（喜欢的食物、颜色、花、音乐等）
- 重要人物（女朋友/男朋友名字、家人信息等）
- 地点信息（住址、常去的地方等）
- 其他有价值的个人信息

【对话内容】
用户: {user_message}
AI: {ai_response[:500]}

请以 JSON 数组格式返回，每个元素是一个对象，包含 content（事实内容）和 category（分类：general/date/preference/person）。
如果没有值得记住的事实，返回空数组 []。
只返回 JSON，不要其他文字。"""

    try:
        if provider_name == "claude":
            cfg = get_claude_config()
            if not cfg["api_key"]:
                return []
            url = f"{cfg['base_url'].rstrip('/')}/v1/messages"
            headers = {
                "x-api-key": cfg["api_key"],
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }
            body = {
                "model": cfg["model"],
                "max_tokens": 500,
                "messages": [{"role": "user", "content": extraction_prompt}],
            }
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.post(url, headers=headers, json=body)
                if resp.status_code != 200:
                    return []
                data = resp.json()
                text = ""
                for block in data.get("content", []):
                    if block.get("type") == "text":
                        text += block.get("text", "")
        else:
            # 默认用 Codex (OpenAI)
            cfg = get_codex_config()
            if not cfg["api_key"]:
                return []
            url = f"{cfg['base_url'].rstrip('/')}/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {cfg['api_key']}",
                "Content-Type": "application/json",
            }
            body = {
                "model": cfg["model"],
                "max_tokens": 500,
                "messages": [{"role": "user", "content": extraction_prompt}],
            }
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.post(url, headers=headers, json=body)
                if resp.status_code != 200:
                    return []
                data = resp.json()
                text = data.get("choices", [{}])[0].get("message", {}).get("content", "")

        # 解析 JSON
        text = text.strip()
        # 去除 markdown 代码块包裹
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

        facts = json.loads(text)
        if not isinstance(facts, list):
            return []

        saved = []
        for fact in facts:
            if isinstance(fact, dict) and fact.get("content"):
                content = str(fact["content"]).strip()
                category = str(fact.get("category", "general")).strip()
                if category not in ("general", "date", "preference", "person"):
                    category = "general"
                save_fact(username, content, category, source="auto")
                saved.append(content)

        if saved:
            logger.info("从对话中提取了 %d 条事实 [%s]", len(saved), username)
        return saved

    except Exception as e:
        logger.warning("事实提取失败: %s", e)
        return []
