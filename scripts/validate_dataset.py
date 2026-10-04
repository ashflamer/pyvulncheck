#!/usr/bin/env python3
"""Validate data/advisories/*.json. Run by CI on every pull request.

Contributors get a precise error instead of a failed test they have to
reverse-engineer.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADVISORIES = ROOT / "src" / "pyvulncheck" / "data" / "advisories"

REQUIRED = {"schema_version", "id", "package", "ecosystem", "symbols", "notes", "reviewed"}
ALLOWED = REQUIRED | {"aliases", "fix_commits", "reviewer_note", "safe_wrappers"}
ID_RE = re.compile(r"^(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|PYSEC-\d{4}-\d+|CVE-\d{4}-\d+)$")
SYMBOL_RE = re.compile(r"^[A-Za-z_][\w.]*$")


def validate(path: Path) -> list[str]:
    errors: list[str] = []

    def bad(message: str) -> None:
        errors.append(f"{path.name}: {message}")

    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{path.name}: invalid JSON ({exc})"]

    missing = REQUIRED - set(record)
    if missing:
        bad(f"missing required field(s): {', '.join(sorted(missing))}")
    unexpected = set(record) - ALLOWED
    if unexpected:
        bad(f"unexpected field(s): {', '.join(sorted(unexpected))}")

    if record.get("schema_version") != "1.0":
        bad("schema_version must be \"1.0\"")
    if record.get("id") != path.stem:
        bad(f"id {record.get('id')!r} must match the filename {path.stem!r}")
    if not ID_RE.match(str(record.get("id", ""))):
        bad(f"id {record.get('id')!r} is not a recognised advisory identifier")
    if record.get("ecosystem") != "PyPI":
        bad("ecosystem must be \"PyPI\"")
    if not isinstance(record.get("reviewed"), bool):
        bad("reviewed must be true or false")

    package = record.get("package", "")
    if package != re.sub(r"[-_.]+", "-", package).lower():
        bad(f"package {package!r} is not PEP 503 normalised")

    symbols = record.get("symbols")
    if not isinstance(symbols, list) or not symbols:
        bad("symbols must be a non-empty list")
    else:
        for symbol in symbols:
            if not isinstance(symbol, str) or not SYMBOL_RE.match(symbol):
                bad(f"symbol {symbol!r} is not a valid dotted path")
            elif "." not in symbol:
                bad(f"symbol {symbol!r} must be fully qualified (module.name)")
        if len(symbols) != len(set(symbols)):
            bad("duplicate entries in symbols")

    notes = record.get("notes", "")
    if not isinstance(notes, str) or len(notes.strip()) < 40:
        bad("notes must explain why these symbols were chosen (40+ characters)")

    for alias in record.get("aliases", []):
        if not ID_RE.match(alias):
            bad(f"alias {alias!r} is not a recognised identifier")

    wrappers = record.get("safe_wrappers", [])
    if not isinstance(wrappers, list):
        bad("safe_wrappers must be a list")
    else:
        for wrapper in wrappers:
            if not isinstance(wrapper, str) or not SYMBOL_RE.match(wrapper):
                bad(f"safe_wrappers entry {wrapper!r} is not a valid dotted path")
            elif wrapper in symbols if isinstance(symbols, list) else False:
                bad(f"{wrapper!r} cannot be both a vulnerable symbol and a safe wrapper")

    for url in record.get("fix_commits", []):
        if not url.startswith("https://"):
            bad(f"fix_commits entry {url!r} must be an https URL")

    return errors


def main() -> int:
    files = sorted(ADVISORIES.glob("*.json"))
    if not files:
        print("no advisory files found", file=sys.stderr)
        return 1

    errors: list[str] = []
    seen_ids: dict[str, str] = {}
    for path in files:
        errors.extend(validate(path))
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for key in [record.get("id"), *record.get("aliases", [])]:
            if key in seen_ids and seen_ids[key] != path.name:
                errors.append(f"{path.name}: id/alias {key!r} already claimed by {seen_ids[key]}")
            seen_ids[key] = path.name

    for error in errors:
        print(f"  {error}", file=sys.stderr)

    if errors:
        print(f"\n{len(errors)} problem(s) in {len(files)} advisory file(s)", file=sys.stderr)
        return 1

    print(f"OK: {len(files)} advisory file(s) valid, {len(seen_ids)} identifiers indexed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
