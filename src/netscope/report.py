"""Self-contained HTML dashboard (one file, no external resources)."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

_PLACEHOLDER = "/*NETSCOPE_DATA*/null"


def embed_json(data: object) -> str:
    """JSON that is safe inside a <script> block.

    Host names come from the network (DNS, NetBIOS) and could contain markup;
    escaping <, > and & stops a name such as "</script>" from breaking out.
    """
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace(" ", "\\u2028")
        .replace(" ", "\\u2029")
    )


def render(scan: dict) -> str:
    template = resources.files("netscope").joinpath("templates/report.html").read_text("utf-8")
    if _PLACEHOLDER not in template:
        raise RuntimeError("report template is missing its data placeholder")
    return template.replace(_PLACEHOLDER, embed_json(scan), 1)


def write_report(scan: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(scan), encoding="utf-8")
    return path
