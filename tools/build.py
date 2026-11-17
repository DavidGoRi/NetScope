"""Build the release artifacts into dist/.

    python tools/build.py pyz      -> dist/netscope.pyz (any OS with Python 3.10+, Android/Termux too)
    python tools/build.py binary   -> dist/netscope-<os>-<arch>[.exe] (no Python needed; PyInstaller)
"""

from __future__ import annotations

import platform
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "netscope"
DIST = ROOT / "dist"
ENTRY = "import sys\nfrom netscope.cli import main\n\nsys.exit(main())\n"


def build_pyz() -> Path:
    DIST.mkdir(exist_ok=True)
    target = DIST / "netscope.pyz"
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp)
        shutil.copytree(PACKAGE, staging / "netscope", ignore=shutil.ignore_patterns("__pycache__"))
        (staging / "__main__.py").write_text(ENTRY, encoding="utf-8")
        zipapp.create_archive(
            staging, target, interpreter="/usr/bin/env python3", compressed=True
        )
    return target


def binary_name() -> str:
    system = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}[platform.system()]
    machine = platform.machine().lower()
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine, machine)
    return f"netscope-{system}-{arch}" + (".exe" if system == "windows" else "")


def build_binary() -> Path:
    import PyInstaller.__main__  # dev dependency, installed only in the release job

    DIST.mkdir(exist_ok=True)
    name = binary_name()
    with tempfile.TemporaryDirectory() as tmp:
        entry = Path(tmp) / "netscope_entry.py"
        entry.write_text(ENTRY, encoding="utf-8")
        templates = PACKAGE / "templates"
        PyInstaller.__main__.run([
            str(entry),
            "--onefile",
            "--console",
            "--clean",
            "--noconfirm",
            "--name", Path(name).stem,
            "--paths", str(ROOT / "src"),
            "--add-data", f"{templates}{__import__('os').pathsep}netscope/templates",
            "--collect-submodules", "netscope",
            "--distpath", str(DIST),
            "--workpath", str(Path(tmp) / "build"),
            "--specpath", tmp,
        ])
    return DIST / name


def main() -> None:
    kind = sys.argv[1] if len(sys.argv) > 1 else "pyz"
    builders = {"pyz": build_pyz, "binary": build_binary}
    if kind not in builders:
        sys.exit(f"usage: python tools/build.py {'|'.join(builders)}")
    print(f"built {builders[kind]()}")


if __name__ == "__main__":
    main()
