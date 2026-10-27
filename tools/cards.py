#!/usr/bin/env python3
"""Собирает карточки для сайта из принятых bundle.

Читает bundles/, прогоняет каждый через гейт (чтобы артефакт не мог содержать
то, что не прошло приём), пишет card.json на bundle и общий index.json.

Детерминированность: одинаковый вход даёт одинаковый выход, кроме поля
generated_at. Хеши считаются по содержимому файлов, поэтому потребитель может
сверить то, что поставил, с тем, что показано на карточке.

  python tools/cards.py --out dist
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


def file_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def bundle_card(bundle_path: Path) -> dict:
    manifest = gate.parse_manifest(bundle_path / "manifest.yaml")
    files = {}
    for f in gate.iter_files(bundle_path):
        files[f.relative_to(bundle_path).as_posix()] = file_hash(f)
    result = gate.check(bundle_path)
    return {
        "schema": "hermes-community-card/1",
        "name": manifest["name"],
        "title": manifest["title"],
        "summary": manifest["summary"],
        "license": manifest["license"],
        "authors": manifest["authors"],
        "tags": manifest.get("tags", []),
        "risk": manifest["risk"],
        "entry": manifest["entry"],
        "compat": manifest.get("compat", {}),
        "tested_on": manifest.get("tested_on"),
        "gate": {
            "ok": result.ok,
            "verdict": result.verdict,
            "rules": result.rules,
            "scanner": "skills-guard",
            "errors": result.errors,
        },
        "files": files,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dist", type=Path)
    args = ap.parse_args()
    out = args.out
    (out / "bundles").mkdir(parents=True, exist_ok=True)

    cards = []
    for d in sorted((REPO_ROOT / "bundles").iterdir()):
        if not d.is_dir() or d.name.startswith("_"):
            continue
        if not (d / "manifest.yaml").is_file():
            print(f"пропуск {d.name}: нет manifest.yaml")
            continue
        card = bundle_card(d)
        if not card["gate"]["ok"]:
            print(f"пропуск {d.name}: гейт FAIL — {card['gate']['errors'][:2]}")
            continue
        (out / "bundles" / f"{d.name}.json").write_text(
            json.dumps(card, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        cards.append(card)

    index = {
        "schema": "hermes-community-index/1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "count": len(cards),
        "bundles": [
            {k: c[k] for k in ("name", "title", "summary", "tags", "risk", "license")}
            | {"authors": [a["github"] for a in c["authors"]], "verdict": c["gate"]["verdict"]}
            for c in cards
        ],
    }
    (out / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n",
                                    encoding="utf-8")
    print(f"карточек: {len(cards)} → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
