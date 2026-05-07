r"""确保服务器数据库已导入随项目发布的 HowToCook 菜谱快照。

部署后可直接执行：
    python tools\ensure_howtocook_recipes.py
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.database import init_tables  # noqa: E402
from backend.services.recipe_bootstrap import ensure_howtocook_recipes_seeded  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="确保 HowToCook 菜谱基础数据已入库")
    parser.add_argument(
        "--source-dir",
        default=str(PROJECT_ROOT / "data" / "upstream" / "howtocook"),
        help="HowToCook 上游快照目录",
    )
    parser.add_argument("--created-by", default="deploy", help="导入批次触发人")
    parser.add_argument("--force", action="store_true", help="即使已有数据也强制重新 upsert")
    args = parser.parse_args()

    init_tables()
    result = ensure_howtocook_recipes_seeded(
        source_dir=Path(args.source_dir),
        created_by=args.created_by,
        force=args.force,
        raise_on_error=True,
    )
    if result.status == "already_seeded":
        print(f"HowToCook recipes already seeded: count={result.existing_count}")
        return 0

    import_result = result.import_result
    if not import_result:
        print(f"HowToCook recipe seed status={result.status}: {result.error_message}")
        return 1

    print(
        "HowToCook seed result: "
        f"status={import_result.status}, total={import_result.total_files}, "
        f"created={import_result.created_count}, updated={import_result.updated_count}, "
        f"skipped={import_result.skipped_count}, failed={import_result.failed_count}, "
        f"source_commit={result.source_commit}"
    )
    return 1 if import_result.status == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
