import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.services.recipe_parser import compute_source_hash, parse_recipe_markdown


def test_parse_howtocook_markdown_extracts_structured_recipe():
    markdown = """# 番茄炒蛋

## 必备原料和工具

- 鸡蛋 3 个
- 番茄 2 个
- 盐 适量

## 操作

1. 鸡蛋打散。
2. 番茄切块。
3. 先炒鸡蛋，再加入番茄。

## 附加内容

- 下次可以少放盐。
"""

    recipe = parse_recipe_markdown(
        markdown,
        source_path="dishes/vegetable_dish/番茄炒蛋/番茄炒蛋.md",
        source_repo="https://github.com/Anduin2017/HowToCook",
        source_commit="abc123",
    )

    assert recipe.title == "番茄炒蛋"
    assert recipe.category == "vegetable_dish"
    assert recipe.source == "howtocook"
    assert recipe.source_repo == "https://github.com/Anduin2017/HowToCook"
    assert recipe.source_commit == "abc123"
    assert recipe.source_path == "dishes/vegetable_dish/番茄炒蛋/番茄炒蛋.md"
    assert recipe.source_hash == compute_source_hash(markdown)
    assert recipe.ingredients == ["鸡蛋 3 个", "番茄 2 个", "盐 适量"]
    assert recipe.steps == ["鸡蛋打散。", "番茄切块。", "先炒鸡蛋，再加入番茄。"]
    assert "少放盐" in recipe.tips
    assert recipe.raw_markdown == markdown


def test_parse_howtocook_markdown_falls_back_to_filename_title():
    markdown = """没有标准标题的内容

## 材料

- 米饭

## 做法

- 翻炒
"""

    recipe = parse_recipe_markdown(
        markdown,
        source_path="dishes/staple/蛋炒饭.md",
        source_commit="abc123",
    )

    assert recipe.title == "蛋炒饭"
    assert recipe.category == "staple"
    assert recipe.ingredients == ["米饭"]
    assert recipe.steps == ["翻炒"]


def test_parse_howtocook_markdown_ignores_bom_and_normalizes_recipe_title():
    markdown = """\ufeff# 咖喱炒蟹的做法

## 必备原料和工具

- 青蟹

## 计算

- 青蟹 1 只 * 份数

## 操作

- 炒熟
"""

    recipe = parse_recipe_markdown(
        markdown,
        source_path="dishes/aquatic/咖喱炒蟹.md",
        source_commit="abc123",
    )

    assert recipe.title == "咖喱炒蟹"
    assert recipe.ingredients == ["青蟹"]
    assert recipe.steps == ["炒熟"]
