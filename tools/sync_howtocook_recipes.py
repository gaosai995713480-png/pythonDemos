r"""同步 HowToCook 上游快照到本项目数据库。

示例：
    python tools\sync_howtocook_recipes.py --source-dir data\upstream\howtocook --source-commit abc123 --dry-run
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.services.recipe_bootstrap import load_howtocook_recipes  # noqa: E402
from backend.services.recipe_importer import RecipeImportService  # noqa: E402


def load_recipes(source_dir: Path, source_commit: str, limit: int | None = None):
    recipes, load_errors, _ = load_howtocook_recipes(
        source_dir,
        source_commit,
        limit=limit,
    )
    return recipes, load_errors


def main() -> int:
    parser = argparse.ArgumentParser(description="同步 HowToCook 菜谱到本项目数据库")
    parser.add_argument("--source-dir", required=True, help="HowToCook 上游快照目录")
    parser.add_argument("--source-commit", default="", help="HowToCook 快照对应 commit")
    parser.add_argument("--limit", type=int, default=None, help="限制导入文件数量")
    parser.add_argument("--dry-run", action="store_true", help="只解析并输出统计，不写数据库")
    parser.add_argument("--force", action="store_true", help="即使源文件 hash 未变化也强制更新解析结果")
    parser.add_argument("--created-by", default="system", help="触发人")
    args = parser.parse_args()

    source_dir = Path(args.source_dir).resolve()
    recipes, load_errors = load_recipes(source_dir, args.source_commit, limit=args.limit)
    service = RecipeImportService()
    result = service.import_recipes(
        recipes,
        load_errors=load_errors,
        source_commit=args.source_commit,
        created_by=args.created_by,
        dry_run=args.dry_run,
        force=args.force,
    )

    print(
        "HowToCook sync result: "
        f"total={result.total_files}, created={result.created_count}, "
        f"updated={result.updated_count}, skipped={result.skipped_count}, "
        f"failed={result.failed_count}, status={result.status}"
    )
    return 1 if result.status == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
