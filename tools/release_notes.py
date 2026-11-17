"""Print the CHANGELOG.md section of a version (used by the release workflow)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"


def section(version: str, text: str) -> str:
    pattern = rf"^## \[?{re.escape(version)}\]?[^\n]*\n(.*?)(?=^## |\Z)"
    match = re.search(pattern, text, flags=re.MULTILINE | re.DOTALL)
    if not match:
        raise SystemExit(f"CHANGELOG.md has no section for {version}")
    return match.group(1).strip()


if __name__ == "__main__":
    print(section(sys.argv[1], CHANGELOG.read_text(encoding="utf-8")))
