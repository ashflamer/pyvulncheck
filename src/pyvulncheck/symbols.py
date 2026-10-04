"""Work out *which functions* an advisory actually makes dangerous.

This is the piece that does not exist anywhere else for PyPI.

Go advisories ship `ecosystem_specific.imports[].symbols`, hand-curated by the
Go security team; that list is what lets govulncheck do reachability. The same
field on a PyPI advisory is empty. So we reconstruct it from two sources:

1. A curated dataset in `data/advisories/` (highest trust, community-editable).
2. Automatic derivation from the advisory's own fix commit - the functions the
   maintainer touched when fixing the bug are, by definition, the vulnerable
   ones.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, Optional

from pyvulncheck.models import Advisory, Confidence, VulnerableSymbol

USER_AGENT = "pyvulncheck (+https://github.com/ashflamer/pyvulncheck)"

# `@@ -273,12 +277,22 @@ def do_xmlattr(` - git appends the enclosing
# definition to each hunk header, which is exactly what we want.
HUNK_CONTEXT_RE = re.compile(r"^@@[^@]*@@\s*(?P<context>.*)$")
DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)")
CLASS_RE = re.compile(r"^\s*class\s+(?P<name>[A-Za-z_]\w*)")
FILE_RE = re.compile(r"^\+\+\+ b/(?P<path>.+)$")

# Paths that never contain shipped, callable library code.
EXCLUDED_PARTS = {
    "test", "tests", "testing", "_test", "docs", "doc", "examples", "example",
    "benchmarks", "scripts", "bin", "setup.py", "conftest.py",
}


def _is_library_source(path: str) -> bool:
    if not path.endswith(".py"):
        return False
    parts = [p.lower() for p in Path(path).parts]
    if any(p in EXCLUDED_PARTS for p in parts):
        return False
    if parts and parts[-1].startswith("test_"):
        return False
    return True


def module_from_path(path: str, top_levels: Iterable[str] = ()) -> Optional[str]:
    """`src/jinja2/filters.py` -> `jinja2.filters`.

    Layouts differ wildly (src/, flat, nested), so when we know the package's
    real top-level import names we anchor on those; otherwise we strip the
    usual wrappers.
    """
    parts = list(Path(path).parts)
    if not parts or not parts[-1].endswith(".py"):
        return None

    parts[-1] = parts[-1][: -len(".py")]
    if parts[-1] == "__init__":
        parts.pop()
    if not parts:
        return None

    tops = {t for t in top_levels if t}
    if tops:
        for index, part in enumerate(parts):
            if part in tops:
                return ".".join(parts[index:])
        # The patch touched a file outside the package we care about.
        return None

    while parts and parts[0] in {"src", "lib", "python", "."}:
        parts.pop(0)
    return ".".join(parts) if parts else None


def parse_patch(patch: str, top_levels: Iterable[str] = ()) -> list[VulnerableSymbol]:
    """Extract the functions/classes a fix commit changed.

    Two signals are combined:
      * the enclosing definition git puts in each `@@` hunk header, and
      * any `def`/`class` line the patch itself adds or removes.
    """
    symbols: list[VulnerableSymbol] = []
    seen: set[tuple[str, str]] = set()

    current_module: Optional[str] = None
    include_file = False
    current_class: Optional[str] = None

    for line in patch.splitlines():
        file_match = FILE_RE.match(line)
        if file_match:
            path = file_match.group("path")
            include_file = _is_library_source(path)
            current_module = module_from_path(path, top_levels) if include_file else None
            include_file = include_file and current_module is not None
            current_class = None
            continue

        if not include_file or current_module is None:
            continue

        hunk = HUNK_CONTEXT_RE.match(line)
        if hunk:
            context = hunk.group("context")
            class_match = CLASS_RE.match(context)
            if class_match:
                current_class = class_match.group("name")
                _add(symbols, seen, current_module, class_match.group("name"))
                continue
            def_match = DEF_RE.match(context)
            if def_match:
                name = def_match.group("name")
                qualified = f"{current_class}.{name}" if current_class else name
                _add(symbols, seen, current_module, qualified)
            continue

        # A changed line that is itself a definition.
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
            body = line[1:]
            class_match = CLASS_RE.match(body)
            if class_match:
                _add(symbols, seen, current_module, class_match.group("name"))
                continue
            def_match = DEF_RE.match(body)
            if def_match:
                name = def_match.group("name")
                # A top-level def (no indentation) is not a method.
                indented = body[:1] in (" ", "\t")
                qualified = f"{current_class}.{name}" if (indented and current_class) else name
                _add(symbols, seen, current_module, qualified)

    return symbols


def _add(out: list, seen: set, module: str, name: str) -> None:
    # Private helpers are real code, but a caller can't reach them directly;
    # keeping them would create paths that no user can actually trigger.
    if name.startswith("__") and not name.endswith("__"):
        return
    key = (module, name)
    if key in seen:
        return
    seen.add(key)
    out.append(VulnerableSymbol(module=module, name=name))


# ----------------------------------------------------------- curated data


def curated_dir() -> Path:
    """Dataset shipped *inside* the package so it survives `pip install`."""
    return Path(__file__).resolve().parent / "data" / "advisories"


def load_curated(directory: Optional[Path] = None) -> dict[str, dict]:
    """Load the hand-reviewed advisory → symbols dataset.

    Keyed by advisory id *and* by every alias, so a lookup works whether the
    caller has a GHSA id, a CVE id, or a PYSEC id.
    """
    directory = Path(directory) if directory else curated_dir()
    index: dict[str, dict] = {}
    if not directory.is_dir():
        return index

    for path in sorted(directory.glob("*.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(record, dict) or "id" not in record:
            continue
        record["_source_file"] = path.name
        for key in [record["id"], *record.get("aliases", [])]:
            index[key.upper()] = record
    return index


def curated_record(advisory_id: str, aliases: Iterable[str], curated: dict) -> Optional[dict]:
    for key in [advisory_id, *aliases]:
        record = curated.get(key.upper())
        if record:
            return record
    return None


def curated_symbols(advisory_id: str, aliases: Iterable[str], curated: dict) -> Optional[list]:
    record = curated_record(advisory_id, aliases, curated)
    if record is None:
        return None
    return [_parse_qualname(s) for s in record.get("symbols", [])]


def safe_wrappers_for(advisory_id: str, aliases: Iterable[str], curated: dict) -> list[str]:
    """Entry points a curated reviewer has marked as *not* a route to the bug.

    See the PyYAML entry: safe_load() calls load() internally, so without this
    every project using the documented safe API would be flagged.
    """
    record = curated_record(advisory_id, aliases, curated)
    return list(record.get("safe_wrappers", [])) if record else []


def _parse_qualname(qualname: str) -> VulnerableSymbol:
    """`jinja2.filters.do_xmlattr` -> module `jinja2.filters`, name `do_xmlattr`.

    Capitalised components are treated as classes so `a.b.Klass.method` keeps
    `Klass.method` together as the symbol name.
    """
    parts = qualname.split(".")
    for index, part in enumerate(parts):
        if part[:1].isupper():
            return VulnerableSymbol(module=".".join(parts[:index]), name=".".join(parts[index:]))
    return VulnerableSymbol(module=".".join(parts[:-1]), name=parts[-1])


# ------------------------------------------------------------- derivation


def patch_urls(commit_urls: Iterable[str]) -> list[str]:
    """Turn GitHub commit/PR links into their `.patch` equivalents."""
    out: list[str] = []
    for url in commit_urls:
        url = url.rstrip("/")
        if url.endswith(".patch"):
            out.append(url)
        elif "/commit/" in url or "/pull/" in url:
            out.append(url + ".patch")
    return list(dict.fromkeys(out))


class PatchFetcher:
    """Downloads commit patches, with the same cache discipline as OSVClient."""

    def __init__(self, cache_dir: Optional[Path] = None, *, offline: bool = False,
                 timeout: float = 30.0, max_bytes: int = 2_000_000) -> None:
        from pyvulncheck.osv import default_cache_dir

        self.cache_dir = Path(cache_dir) if cache_dir else default_cache_dir() / "patches"
        self.offline = offline
        self.timeout = timeout
        self.max_bytes = max_bytes

    def fetch(self, url: str) -> Optional[str]:
        import hashlib

        key = hashlib.sha256(url.encode()).hexdigest()[:20]
        path = self.cache_dir / f"{key}.patch"
        if path.exists():
            try:
                return path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        if self.offline:
            return None

        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(self.max_bytes)
        except (urllib.error.URLError, TimeoutError, OSError):
            return None

        text = raw.decode("utf-8", errors="replace")
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except OSError:
            pass
        return text


def resolve_symbols(
    advisory: Advisory,
    *,
    curated: dict,
    fetcher: Optional[PatchFetcher] = None,
    top_levels: Iterable[str] = (),
    max_patches: int = 3,
) -> tuple[list[VulnerableSymbol], Confidence]:
    """Best available symbol list for an advisory, with its provenance."""
    found = curated_symbols(advisory.id, advisory.aliases, curated)
    if found:
        return found, Confidence.CURATED

    if fetcher is None:
        return [], Confidence.NONE

    symbols: list[VulnerableSymbol] = []
    seen: set[str] = set()
    for url in patch_urls(advisory.fix_commits)[:max_patches]:
        patch = fetcher.fetch(url)
        if not patch:
            continue
        for symbol in parse_patch(patch, top_levels):
            if symbol.qualname not in seen:
                seen.add(symbol.qualname)
                symbols.append(symbol)

    if symbols:
        return symbols, Confidence.DERIVED
    return [], Confidence.NONE
