"""HowToCook 菜谱 Markdown 解析器。

该模块只负责把上游快照中的 Markdown 转成结构化数据，不访问数据库。
运行时 API 不依赖本模块读取 Markdown；它仅供同步脚本/导入流程使用。
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath


DEFAULT_SOURCE = "howtocook"
DEFAULT_SOURCE_REPO = "https://github.com/Anduin2017/HowToCook"

INGREDIENT_HEADINGS = ("必备原料和工具", "必备原料", "原料", "材料", "食材")
STEP_HEADINGS = ("操作", "步骤", "做法", "制作步骤")
TIP_HEADINGS = ("附加内容", "小贴士", "注意事项", "提示")


@dataclass(frozen=True)
class ParsedRecipe:
    """结构化菜谱草稿。"""

    source: str
    source_repo: str
    source_commit: str
    source_path: str
    source_hash: str
    title: str
    category: str
    description: str
    raw_markdown: str
    ingredients: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    tips: str = ""
    difficulty: str = "unknown"
    cook_time_minutes: int | None = None
    servings: int | None = None
    tags: list[str] = field(default_factory=list)


def compute_source_hash(markdown: str) -> str:
    """计算源 Markdown 的 SHA256。"""
    return hashlib.sha256(markdown.encode("utf-8")).hexdigest()


def parse_recipe_markdown(
    markdown: str,
    *,
    source_path: str,
    source_repo: str = DEFAULT_SOURCE_REPO,
    source_commit: str = "",
    source: str = DEFAULT_SOURCE,
) -> ParsedRecipe:
    """解析 HowToCook 菜谱 Markdown。

    解析策略保守：尽量提取标题、分类、材料、步骤和小贴士；不确定的内容保留在
    raw_markdown 中，避免因为格式差异造成信息损失。
    """
    normalized_path = _normalize_source_path(source_path)
    sections = _split_sections(markdown)
    title = _extract_title(markdown) or _title_from_path(normalized_path)
    category = _category_from_path(normalized_path)
    ingredients = _extract_list_section(sections, INGREDIENT_HEADINGS)
    steps = _extract_list_section(sections, STEP_HEADINGS)
    tips = "\n".join(_extract_list_section(sections, TIP_HEADINGS)).strip()
    description = _extract_description(markdown, title)
    tags = [category] if category else []

    return ParsedRecipe(
        source=source,
        source_repo=source_repo,
        source_commit=source_commit,
        source_path=normalized_path,
        source_hash=compute_source_hash(markdown),
        title=title,
        category=category,
        description=description,
        raw_markdown=markdown,
        ingredients=ingredients,
        steps=steps,
        tips=tips,
        tags=tags,
    )


def _normalize_source_path(source_path: str) -> str:
    return source_path.replace("\\", "/").strip("/")


def _extract_title(markdown: str) -> str:
    for line in markdown.splitlines():
        stripped = line.strip().lstrip("\ufeff").strip()
        if stripped.startswith("#"):
            title = stripped.lstrip("#").strip()
            if title and not _is_known_section_heading(title):
                return _normalize_title(title)
    return ""


def _is_known_section_heading(title: str) -> bool:
    candidates = INGREDIENT_HEADINGS + STEP_HEADINGS + TIP_HEADINGS
    normalized = title.strip()
    return normalized in candidates


def _title_from_path(source_path: str) -> str:
    path = PurePosixPath(source_path)
    stem = path.stem.strip()
    if stem.lower() == "readme" and path.parent.name:
        return path.parent.name
    return _normalize_title(stem or path.parent.name or "未命名菜谱")


def _normalize_title(title: str) -> str:
    title = title.strip()
    for suffix in ("的做法", "做法"):
        if title.endswith(suffix) and len(title) > len(suffix):
            return title[: -len(suffix)].strip()
    return title


def _category_from_path(source_path: str) -> str:
    parts = PurePosixPath(source_path).parts
    try:
        dishes_index = parts.index("dishes")
    except ValueError:
        return parts[0] if len(parts) > 1 else ""
    category_index = dishes_index + 1
    if category_index < len(parts) - 1:
        return parts[category_index]
    return ""


def _split_sections(markdown: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current_heading = ""
    for line in markdown.splitlines():
        heading_match = re.match(r"^\s{0,3}#{2,6}\s+(.+?)\s*$", line)
        if heading_match:
            current_heading = _clean_heading(heading_match.group(1))
            sections.setdefault(current_heading, [])
            continue
        if current_heading:
            sections.setdefault(current_heading, []).append(line)
    return sections


def _clean_heading(heading: str) -> str:
    return heading.strip().strip("#").strip()


def _extract_list_section(
    sections: dict[str, list[str]], heading_candidates: tuple[str, ...]
) -> list[str]:
    for heading, lines in sections.items():
        if any(candidate in heading for candidate in heading_candidates):
            return _lines_to_items(lines)
    return []


def _lines_to_items(lines: list[str]) -> list[str]:
    items: list[str] = []
    paragraph: list[str] = []

    def flush_paragraph() -> None:
        if paragraph:
            text = " ".join(paragraph).strip()
            if text:
                items.append(text)
            paragraph.clear()

    for line in lines:
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            continue
        if stripped.startswith(">"):
            stripped = stripped.lstrip(">").strip()
        match = re.match(r"^(?:[-*+]\s+|\d+[.)、]\s*)(.+)$", stripped)
        if match:
            flush_paragraph()
            item = match.group(1).strip()
            if item:
                items.append(item)
            continue
        if stripped.startswith("#"):
            flush_paragraph()
            continue
        paragraph.append(stripped)

    flush_paragraph()
    return items


def _extract_description(markdown: str, title: str) -> str:
    for line in markdown.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!["):
            continue
        cleaned = re.sub(r"\s+", " ", stripped)
        if cleaned and cleaned != title:
            return cleaned[:500]
    return ""
