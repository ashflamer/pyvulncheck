"""Find what's installed, and where its source lives.

Two jobs that sound trivial and are not:

1. Distribution name != import name. You `pip install PyYAML` and then
   `import yaml`; `beautifulsoup4` becomes `bs4`. Advisories are published
   against the *distribution* name while source code imports the *module*
   name, so every reachability tool needs this mapping or it silently
   finds nothing.

2. Python ships real source in site-packages. Unlike Go or Rust binaries,
   we can read our dependencies' code and walk into it - which is how a
   two-hop path like yours -> jinja2.Environment -> do_xmlattr gets found.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Iterable, Optional

# Standard library top-level names never come from PyPI.
_STDLIB = set(getattr(sys, "stdlib_module_names", ())) | {
    "os", "sys", "re", "json", "ast", "typing", "pathlib", "dataclasses",
}


@dataclass
class Package:
    """An installed distribution."""

    name: str              # normalised distribution name, e.g. "pyyaml"
    raw_name: str          # as declared, e.g. "PyYAML"
    version: str
    top_levels: list[str] = field(default_factory=list)   # import names
    location: Optional[Path] = None

    def __str__(self) -> str:
        return f"{self.raw_name}=={self.version}"


def normalise(name: str) -> str:
    """PEP 503 normalisation."""
    import re

    return re.sub(r"[-_.]+", "-", name).lower()


def _top_levels_for(dist: metadata.Distribution, fallback: str) -> list[str]:
    """Work out which import names a distribution provides."""
    names: list[str] = []

    # Fast path: the metadata file that exists precisely for this.
    try:
        text = dist.read_text("top_level.txt")
    except Exception:
        text = None
    if text:
        names = [line.strip() for line in text.splitlines() if line.strip()]
        # Stub-only and namespace entries are not importable module names.
        names = [n for n in names if n.isidentifier()]
        if names:
            return sorted(set(names))

    # Slow path: infer from the installed file list.
    try:
        files = dist.files or []
    except Exception:
        files = []
    candidates: set[str] = set()
    for file in files:
        parts = Path(str(file)).parts
        if not parts:
            continue
        head = parts[0]
        if head.endswith((".dist-info", ".egg-info", ".data")) or head in {"..", "."}:
            continue
        if head == "__pycache__" or (head.startswith("__") and head.endswith("__")):
            continue
        if "__mypyc" in head or head.endswith(".so") or head.endswith(".pyd"):
            continue
        if len(parts) > 1 and head.isidentifier():
            candidates.add(head)
        elif head.endswith(".py"):
            stem = head[:-3]
            if stem.isidentifier():
                candidates.add(stem)
    if candidates:
        return sorted(candidates)

    guess = fallback.replace("-", "_")
    return [guess] if guess.isidentifier() else []


def installed_packages(paths: Optional[Iterable[str]] = None) -> dict[str, Package]:
    """Every installed distribution, keyed by normalised name."""
    out: dict[str, Package] = {}
    dists = metadata.distributions(path=list(paths)) if paths else metadata.distributions()

    for dist in dists:
        try:
            raw = dist.metadata["Name"]
            version = dist.version
        except Exception:
            continue
        if not raw:
            continue
        key = normalise(raw)
        if key in out:
            continue
        location = None
        try:
            located = getattr(dist, "_path", None)
            if located:
                location = Path(located).parent
        except Exception:
            pass
        out[key] = Package(
            name=key, raw_name=raw, version=version,
            top_levels=_top_levels_for(dist, key), location=location,
        )
    return out


def parse_requirements(path: Path) -> dict[str, str]:
    """Read pinned versions out of a requirements.txt-style file.

    Only exact `==` pins are usable for vulnerability matching; ranges are
    reported so the user knows what was skipped.
    """
    pins: dict[str, str] = {}
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return pins

    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()       # drop environment markers
        if "==" not in line:
            continue
        name, _, version = line.partition("==")
        name = name.split("[", 1)[0].strip()       # drop extras
        version = version.strip()
        if name and version:
            pins[normalise(name)] = version
    return pins


def module_files_for(package: Package, *, max_files: int = 400) -> dict[str, Path]:
    """Map every module in a package to its source file.

    Called only for packages that actually have advisories, so the cost of
    parsing dependency source stays proportional to the risk, not to the size
    of the virtualenv.
    """
    from pyvulncheck.callgraph import iter_python_files, module_name_for

    out: dict[str, Path] = {}
    if not package.location:
        return out

    for top in package.top_levels:
        if top in _STDLIB:
            continue
        directory = package.location / top
        single = package.location / f"{top}.py"

        if directory.is_dir():
            for file in iter_python_files(directory)[:max_files]:
                module = module_name_for(file, package.location)
                if module:
                    out[module] = file
        elif single.is_file():
            out[top] = single

    return out


def resolve_scan_targets(
    advisory_packages: Iterable[str], installed: dict[str, Package]
) -> dict[str, Path]:
    """Source files to parse, for just the packages carrying advisories."""
    targets: dict[str, Path] = {}
    for name in advisory_packages:
        package = installed.get(normalise(name))
        if package:
            targets.update(module_files_for(package))
    return targets


def import_name_index(installed: dict[str, Package]) -> dict[str, str]:
    """import name -> distribution name (the reverse of the usual mapping)."""
    index: dict[str, str] = {}
    for package in installed.values():
        for top in package.top_levels:
            index.setdefault(top, package.name)
    return index
