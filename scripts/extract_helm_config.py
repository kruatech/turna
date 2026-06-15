#!/usr/bin/env python3
"""Extract data.turn.toml from a Helm-rendered ConfigMap.

The CI packaging job uses this tiny stdlib-only helper so it does not depend on
PyYAML/yq being installed on GitHub runners. It intentionally validates the
shape we need instead of attempting to be a generic YAML parser.
"""

from __future__ import annotations

import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"extract_helm_config.py: {message}", file=sys.stderr)
    raise SystemExit(1)


def extract(rendered_yaml: str) -> str:
    docs = rendered_yaml.split("\n---")
    for doc in docs:
        if "kind: ConfigMap" not in doc:
            continue
        if "turn.toml:" not in doc:
            continue

        lines = doc.splitlines()
        for i, line in enumerate(lines):
            if line.strip() == "turn.toml: |":
                block: list[str] = []
                for raw in lines[i + 1 :]:
                    if not raw.startswith("    "):
                        break
                    block.append(raw[4:])
                text = "\n".join(block).rstrip() + "\n"
                if "[turn]" not in text or "[turn.auth]" not in text:
                    fail("extracted turn.toml does not look like the current schema")
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
