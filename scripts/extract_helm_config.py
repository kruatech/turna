#!/usr/bin/env python3
"""Extract data.turn.toml from a Helm-rendered ConfigMap.
Stdlib-only helper for the CI packaging job (no PyYAML/yq on runners). Extracts
the turn.toml block; schema validation is left to turna-config (the cargo test
that actually parses the file), not duplicated here.
"""
from __future__ import annotations
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"extract_helm_config.py: {message}", file=sys.stderr)
    raise SystemExit(1)


def extract(rendered_yaml: str) -> str:
    for doc in rendered_yaml.split("\n---"):
        if "kind: ConfigMap" not in doc or "turn.toml:" not in doc:
            continue
        lines = doc.splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"^(\s*)turn\.toml:\s*\|", line)
            if not m:
                continue
            key_indent = len(m.group(1))
            block: list[str] = []
            for raw in lines[i + 1:]:
                if raw.strip() == "":
                    block.append("")
                    continue
                indent = len(raw) - len(raw.lstrip())
                if indent <= key_indent:
                    break
                block.append(raw)
            while block and block[-1] == "":
                block.pop()
            if not block:
                continue
            indents = [len(b) - len(b.lstrip()) for b in block if b.strip()]
            d = min(indents) if indents else 0
            text = "\n".join(b[d:] if b.strip() else "" for b in block).rstrip() + "\n"
            if not text.strip() or "[" not in text:
                fail("extracted turn.toml block is empty or not TOML-shaped")
            return text
    fail("no ConfigMap data.turn.toml block found in rendered manifest")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        fail("usage: extract_helm_config.py <rendered.yaml> <out.toml>")
    src = Path(argv[1])
    dst = Path(argv[2])
    if not src.exists():
        fail(f"input not found: {src}")
    dst.write_text(extract(src.read_text()), encoding="utf-8")
    print(f"wrote {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
