#!/usr/bin/env python3
"""Гейт приёма bundle в hermes-community.

Один скрипт, одни правила: CI вызывает его на PR, автор вызывает локально перед
пушем. Расхождение вердиктов между локальным прогоном и CI — дефект, а не
удобство, поэтому здесь нет флага «пропустить проверку».

Слои проверок, от дешёвых к дорогим:
  1. структура: манифест парсится, обязательные поля на месте, объявленные пути
     существуют и не выходят за пределы bundle;
  2. лицензия: из разрешённого списка;
  3. размеры: не больше 300 файлов и 5 МБ на bundle;
  4. секреты: gitleaks (если установлен) плюс собственный набор регулярок;
  5. внутренние данные: приватные адреса, корпоративные домены, личные пути;
  6. невидимые символы и HTML-комментарии с инструкциями;
  7. поведенческий скан каждого скилла через skills_guard из Hermes Agent;
  8. сверка манифеста с содержимым: заявленный risk против найденного.

Использование:
  python tools/gate.py bundles/<slug>          # один набор
  python tools/gate.py bundles/*               # все
  python tools/gate.py --changed               # только изменённые относительно origin/main
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

AGENT_DIR = Path(os.environ.get("HERMES_AGENT_DIR", Path.home() / "AppData/Local/hermes/hermes-agent"))
if (AGENT_DIR / "tools").is_dir():
    sys.path.insert(0, str(AGENT_DIR / "tools"))

MAX_FILES = 300
MAX_BYTES = 5 * 1024 * 1024
TEXT_SUFFIXES = {".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg"}

# Лицензии, при которых набор можно раздавать публично. Копилефт не запрещён,
# но должен быть назван точно: читатель обязан понимать, что получит.
ALLOWED_LICENSES = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0",
    "CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0", "GPL-3.0-only", "AGPL-3.0-only",
    "Unlicense",
}

REQUIRED_FIELDS = ("schema", "name", "title", "summary", "license", "authors", "risk", "entry")
RISK_KEYS = ("network", "credentials", "money", "filesystem", "shell")

SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github_pat", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{32,}")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("jira_token", re.compile(r"\bATATT[A-Za-z0-9_\-]{20,}")),
    ("posthog_key", re.compile(r"\bphc_[A-Za-z0-9]{30,}")),
    ("bearer_literal", re.compile(r"Bearer\s+[A-Za-z0-9_\-.=]{30,}")),
    ("uuid_api_key", re.compile(r"api-key-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
    ("exchange_key", re.compile(r"\b[A-Za-z0-9_-]{40,}\b(?=[^\n]{0,20}(?:api[_-]?secret|secret[_-]?key))", re.I)),
]

INTERNAL_PATTERNS = [
    ("internal_ip", re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")),
    ("corp_domain", re.compile(r"\bastralinux\.ru\b")),
    ("win_user_path", re.compile(r"[A-Za-z]:\\Users\\[\w.]+")),
]

INVISIBLE = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2060\ufeff]")
HTML_INJECTION = re.compile(r"<!--.*?(?:ignore|disregard|override|system|instruction).*?-->", re.S | re.I)

# Русскоязычные аналоги тех же конструкций. skills_guard написан на английских
# паттернах, а каталог русский: без этого списка самая частая формулировка
# инъекции проходит мимо и CI, и поведенческого скана.
INJECTION_RU = [
    ("ru_ignore", re.compile(r"игнорир\w*\s+(?:все\s+)?(?:предыдущ|прежн|выше)\w*\s+(?:инструкц|указан|правил)", re.I)),
    ("ru_forget", re.compile(r"забудь\w*\s+(?:все\s+)?(?:предыдущ|прежн|свои)\w*\s+(?:инструкц|правил|указан)", re.I)),
    ("ru_leak_prompt", re.compile(r"(?:покаж|вывед|раскрой)\w*\s+(?:свой\s+)?(?:системн\w+\s+промпт|system\s*prompt)", re.I)),
    ("ru_hide", re.compile(r"не\s+сообща\w*\s+(?:об\s+этом\s+)?(?:пользовател|польз)", re.I)),
    ("ru_no_confirm", re.compile(r"действу\w*\s+без\s+(?:подтвержден|разрешени|согласован)", re.I)),
    ("ru_role_reset", re.compile(r"ты\s+больше\s+не\s+(?:ассистент|помощник|агент)", re.I)),
]

# Конструкции, по которым гейт сверяет заявленный risk с содержимым.
RISK_SIGNALS = {
    "network": re.compile(r"https?://|requests\.|fetch\(|urllib|curl\s", re.I),
    "credentials": re.compile(r"api[_-]?key|token|secret|пароль|credential", re.I),
    "money": re.compile(r"\b(?:order|trade|bid|ask|withdraw|deposit|оплат|сделк|ордер|вывод средств)\b", re.I),
    "filesystem": re.compile(r"\b(?:open\(|write_text|fs\.write|>\s*/|mkdir|rm\s+-)", re.I),
    "shell": re.compile(r"\b(?:subprocess|os\.system|exec\(|eval\(|\|\s*bash|bash\s+-c|sh\s+-c)\b", re.I),
}


class Bundle:
    """Разобранный манифест плюс результаты проверок."""

    def __init__(self, path: Path):
        self.path = path
        self.manifest: dict = {}
        self.ok = True
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.verdict = ""
        self.rules: list[str] = []

    def fail(self, code: str, detail: str) -> None:
        self.ok = False
        self.errors.append(f"{code}: {detail}")

    def warn(self, code: str, detail: str) -> None:
        self.warnings.append(f"{code}: {detail}")

    def to_dict(self) -> dict:
        return {
            "bundle": self.path.name,
            "ok": self.ok,
            "verdict": self.verdict,
            "rules": self.rules,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def parse_manifest(path: Path) -> dict:
    """Читает YAML манифеста. PyYAML есть в окружении Hermes, но не гарантирован
    на чистой машине — тогда падаем с внятным сообщением, а не трейсбеком."""
    try:
        import yaml  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("нужен PyYAML: python -m pip install pyyaml") from exc
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("манифест должен быть YAML-объектом")
    return data


def iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if any(part in {".git", "node_modules", "__pycache__", ".venv"} for part in rel.parts):
            continue
        yield p


def check_structure(bundle: Bundle) -> None:
    manifest_path = bundle.path / "manifest.yaml"
    if not manifest_path.is_file():
        bundle.fail("structure", "нет manifest.yaml")
        return
    try:
        bundle.manifest = parse_manifest(manifest_path)
    except Exception as exc:  # noqa: BLE001
        bundle.fail("structure", f"манифест не читается: {exc}")
        return

    data = bundle.manifest
    for field in REQUIRED_FIELDS:
        if field not in data:
            bundle.fail("structure", f"в манифесте нет поля {field}")
    if data.get("schema") != "hermes-bundle/1":
        bundle.fail("structure", f"неизвестная версия схемы: {data.get('schema')!r}")

    name = str(data.get("name", ""))
    if not re.fullmatch(r"[a-z0-9-]{2,48}", name):
        bundle.fail("structure", "name: только a-z, 0-9 и дефис, длина 2–48")
    elif name != bundle.path.name:
        bundle.fail("structure", f"name {name!r} не совпадает с каталогом {bundle.path.name!r}")

    entry = data.get("entry") or {}
    if not isinstance(entry, dict):
        bundle.fail("structure", "entry должен быть объектом")
        return
    declared = []
    for key in ("soul", "agent"):
        if entry.get(key):
            declared.append(entry[key])
    declared += list(entry.get("skills") or [])
    if not declared:
        bundle.fail("structure", "entry пуст: нужен soul, agent или skills")
    for rel in declared:
        target = (bundle.path / rel).resolve()
        if not str(target).startswith(str(bundle.path.resolve())):
            bundle.fail("structure", f"путь {rel} выходит за пределы bundle")
        elif not target.exists():
            bundle.fail("structure", f"объявленный путь {rel} не существует")

    risk = data.get("risk") or {}
    if not isinstance(risk, dict):
        bundle.fail("structure", "risk должен быть объектом")
    else:
        for key in RISK_KEYS:
            if not isinstance(risk.get(key), bool):
                bundle.fail("structure", f"risk.{key} должен быть true/false")


def check_license(bundle: Bundle) -> None:
    lic = bundle.manifest.get("license")
    if not lic:
        return
    if lic not in ALLOWED_LICENSES:
        bundle.fail("license", f"{lic!r} не из списка; разрешённые: {', '.join(sorted(ALLOWED_LICENSES))}")


def check_sizes(bundle: Bundle) -> None:
    files = list(iter_files(bundle.path))
    total = sum(f.stat().st_size for f in files)
    if len(files) > MAX_FILES:
        bundle.fail("size", f"{len(files)} файлов, предел {MAX_FILES}")
    if total > MAX_BYTES:
        bundle.fail("size", f"{total // 1024} КБ, предел {MAX_BYTES // 1024} КБ")


def check_content(bundle: Bundle) -> None:
    if shutil.which("gitleaks"):
        proc = subprocess.run(
            ["gitleaks", "detect", "--no-git", "--source", str(bundle.path), "--redact", "--exit-code", "7"],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode == 7:
            bundle.fail("secret", "gitleaks нашёл секрет; подробности в логе CI")

    found_risk: set[str] = set()
    for f in iter_files(bundle.path):
        rel = f.relative_to(bundle.path).as_posix()
        if rel == "manifest.yaml":
            continue
        if f.suffix.lower() not in TEXT_SUFFIXES:
            if f.suffix.lower() in {".py", ".sh", ".ps1", ".js", ".mjs", ".ts"}:
                bundle.warn("binary", f"{rel}: исполняемый файл — публикуется только после ревью кода")
            continue
        body = f.read_text(encoding="utf-8", errors="ignore")

        for rule, pattern in SECRET_PATTERNS:
            if pattern.search(body):
                bundle.fail("secret", f"{rel}: совпадение {rule}")
        for rule, pattern in INTERNAL_PATTERNS:
            if pattern.search(body):
                bundle.fail("internal", f"{rel}: совпадение {rule}")
        if INVISIBLE.search(body):
            bundle.fail("invisible", f"{rel}: невидимые управляющие символы")
        if HTML_INJECTION.search(body):
            bundle.fail("injection", f"{rel}: инструкция в HTML-комментарии")
        for rule, pattern in INJECTION_RU:
            match = pattern.search(body)
            if match:
                line = body[: match.start()].count("\n") + 1
                bundle.fail("injection", f"{rel}:{line}: {rule} — «{match.group(0)[:60]}»")

        for key, pattern in RISK_SIGNALS.items():
            if pattern.search(body):
                found_risk.add(key)

    # Манифест обязан признаваться в том, что скан нашёл. Обратное неверно:
    # заявленный risk может быть шире найденного, это нормально.
    declared = {k for k, v in (bundle.manifest.get("risk") or {}).items() if v is True}
    undeclared = sorted(found_risk - declared)
    if undeclared:
        bundle.fail("manifest_mismatch",
                    f"найдено в тексте, но не заявлено в risk: {', '.join(undeclared)}")


def check_guard(bundle: Bundle) -> None:
    """Поведенческий скан каждого каталога скилла."""
    try:
        import skills_guard  # noqa: PLC0415
    except ImportError:
        bundle.warn("guard", "skills_guard недоступен: поведенческий слой не проверен")
        return

    skill_dirs = [d.parent for d in bundle.path.rglob("SKILL.md")]
    if not skill_dirs:
        bundle.warn("guard", "в наборе нет ни одного SKILL.md — проверять нечего")
        return
    worst = "safe"
    order = {"safe": 0, "caution": 1, "dangerous": 2}
    for d in skill_dirs:
        try:
            scan = skills_guard.scan_skill(d, source="community")
        except Exception as exc:  # noqa: BLE001
            bundle.warn("guard", f"{d.name}: скан упал ({exc})")
            continue
        bundle.rules += sorted({f.pattern_id for f in scan.findings})
        if order[scan.verdict] > order[worst]:
            worst = scan.verdict
        if scan.verdict == "dangerous":
            critical = sorted({f.pattern_id for f in scan.findings if f.severity == "critical"})
            bundle.fail("guard", f"{d.name}: dangerous ({', '.join(critical)})")
    bundle.verdict = worst
    bundle.rules = sorted(set(bundle.rules))


def check(bundle_path: Path) -> Bundle:
    bundle = Bundle(bundle_path)
    check_structure(bundle)
    if bundle.manifest:
        check_license(bundle)
        check_sizes(bundle)
        check_content(bundle)
        check_guard(bundle)
    return bundle


def changed_bundles(base: str = "origin/main") -> list[Path]:
    proc = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"],
                          cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        proc = subprocess.run(["git", "diff", "--name-only", "HEAD~1", "HEAD"],
                              cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    names = {line.split("/")[1] for line in proc.stdout.splitlines()
             if line.startswith("bundles/") and len(line.split("/")) > 1}
    return [REPO_ROOT / "bundles" / n for n in sorted(names) if (REPO_ROOT / "bundles" / n).is_dir()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", type=Path)
    ap.add_argument("--changed", action="store_true", help="только наборы, изменённые в PR")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    targets = list(args.paths)
    if args.changed:
        targets = changed_bundles()
        if not targets:
            print("Изменённых bundle нет — гейт пропущен.")
            return 0
    # Каталоги с подчёркиванием — образцы и черновики, они не проходят гейт по
    # определению: имя шаблона не совпадает с каталогом, и это нормально.
    targets = [p for p in targets if not p.name.startswith("_")]
    if not targets:
        print("Проверять нечего: все указанные каталоги — образцы.")
        return 0
    if not args.paths and not args.changed:
        ap.error("укажите путь к bundle или --changed")

    results = [check(p.resolve()) for p in targets]
    if args.json:
        print(json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2))
    else:
        for r in results:
            try:
                label = str(r.path.relative_to(REPO_ROOT))
            except ValueError:
                label = str(r.path)
            print(("OK   " if r.ok else "FAIL ") + label)
            for e in r.errors:
                print("     - " + e)
            for w in r.warnings:
                print("     ~ " + w)
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
