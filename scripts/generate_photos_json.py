from __future__ import annotations

import json
from pathlib import Path


IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"}


def generate_for(base_dir: Path) -> None:
    photos_dir = base_dir / "photos"
    output_path = base_dir / "photos.json"

    images = []
    if photos_dir.exists():
        for item in photos_dir.iterdir():
            if not item.is_file():
                continue
            if item.name.startswith("."):
                continue
            if item.suffix.lower() in IMAGE_SUFFIXES:
                images.append(f"photos/{item.name}")

    images.sort()
    output_path.write_text(
        json.dumps(images, ensure_ascii=True, indent=2), encoding="utf-8"
    )


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    for name in ("docs", "static"):
        base_dir = repo_root / name
        if base_dir.exists():
            generate_for(base_dir)


if __name__ == "__main__":
    main()
