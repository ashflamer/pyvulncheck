"""Tie the pieces together: packages -> advisories -> symbols -> verdicts."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from pyvulncheck.callgraph import CallGraph, build_call_graph, iter_python_files
from pyvulncheck.discovery import (
    Package, installed_packages, module_files_for, normalise, parse_requirements,
)
from pyvulncheck.models import Advisory, Confidence, Finding, Reachability
from pyvulncheck.osv import OSVClient, fix_commits_of, fixed_versions_of, severity_of
from pyvulncheck.reachability import MAX_DEPTH, assess
from pyvulncheck.symbols import (
    PatchFetcher, load_curated, resolve_symbols, safe_wrappers_for,
)

Progress = Callable[[str], None]


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    graph: Optional[CallGraph] = None
    errors: list[str] = field(default_factory=list)

    @property
    def actionable(self) -> list[Finding]:
        return [f for f in self.findings if f.actionable]


def _noop(message: str) -> None:  # pragma: no cover - default callback
    pass


def scan(
    target: Path,
    *,
    requirements: Optional[Path] = None,
    offline: bool = False,
    derive_symbols: bool = True,
    follow_dependencies: bool = True,
    max_depth: int = MAX_DEPTH,
    curated_dir: Optional[Path] = None,
    client: Optional[OSVClient] = None,
    fetcher: Optional[PatchFetcher] = None,
    progress: Progress = _noop,
) -> ScanResult:
    """Run a full reachability scan over `target`."""
    target = Path(target).resolve()
    result = ScanResult()

    # 1. What is installed - or, with -r, what the project declares?
    environment = installed_packages()
    if requirements:
        # Matching pip-audit: -r audits that file, not the ambient venv.
        pins = parse_requirements(requirements)
        progress(f"Read {len(pins)} pinned requirement(s) from {requirements.name}")
        packages = {}
        for name, version in pins.items():
            installed = environment.get(name)
            packages[name] = Package(
                name=name,
                raw_name=installed.raw_name if installed else name,
                version=version,
                # Import names come from the installed copy when there is one;
                # otherwise fall back to the usual dist-name -> module guess.
                top_levels=installed.top_levels if installed else [name.replace("-", "_")],
                location=installed.location if installed else None,
            )
        missing = [n for n in packages if n not in environment]
        if missing:
            progress(
                f"{len(missing)} requirement(s) not installed here; "
                "using name-based import mapping for those"
            )
    else:
        progress("Discovering installed packages")
        packages = environment

    if not packages:
        result.errors.append("No packages to scan.")
        return result

    # 2. Which of them have advisories?
    progress(f"Querying OSV.dev for {len(packages)} packages")
    client = client or OSVClient(offline=offline)
    query = [(p.name, p.version) for p in packages.values()]
    try:
        matches = client.query_batch(query)
    except Exception as error:
        result.errors.append(f"OSV query failed: {error}")
        return result

    vuln_ids: list[str] = []
    owner: dict[str, tuple[str, str]] = {}
    for (name, version), ids in matches.items():
        for vuln_id in ids:
            if vuln_id not in owner:
                owner[vuln_id] = (name, version)
                vuln_ids.append(vuln_id)

    progress(f"{len(vuln_ids)} advisories affect installed packages")
    if not vuln_ids:
        result.stats = {"packages": len(packages), "advisories": 0, "files": 0}
        return result

    # 3. Full advisory records, then symbols for each.
    curated = load_curated(curated_dir)
    fetcher = fetcher or (PatchFetcher(offline=offline) if derive_symbols else None)

    advisories: list[tuple[Advisory, Package, list, Confidence]] = []
    derived_count = curated_count = 0

    for index, vuln_id in enumerate(vuln_ids, 1):
        if index % 10 == 0:
            progress(f"Resolving symbols {index}/{len(vuln_ids)}")
        record = client.get_vuln(vuln_id)
        if not record:
            continue
        name, version = owner[vuln_id]
        package = packages[name]
        advisory = Advisory(
            id=record.get("id", vuln_id),
            package=package.raw_name,
            installed_version=version,
            summary=record.get("summary", ""),
            details=record.get("details", "")[:2000],
            aliases=list(record.get("aliases", [])),
            severity=severity_of(record),
            fixed_versions=fixed_versions_of(record, name),
            fix_commits=fix_commits_of(record),
        )
        symbols, confidence = resolve_symbols(
            advisory, curated=curated, fetcher=fetcher, top_levels=package.top_levels,
        )
        advisory.symbols = symbols
        advisory.symbol_confidence = confidence
        if confidence is Confidence.CURATED:
            curated_count += 1
        elif confidence is Confidence.DERIVED:
            derived_count += 1
        advisories.append((advisory, package, symbols, confidence))

    advisories = _deduplicate(advisories)

    # 4. Build the call graph - first-party code plus only the dependencies
    #    that actually carry advisories.
    dependency_modules: dict[str, Path] = {}
    if follow_dependencies:
        affected = {package.name for _, package, _, _ in advisories}
        progress(f"Parsing source of {len(affected)} affected package(s)")
        for name in sorted(affected):
            package = packages.get(name)
            if package:
                dependency_modules.update(module_files_for(package))

    progress("Building call graph")
    graph = build_call_graph([target], dependency_modules=dependency_modules)
    result.graph = graph

    # 5. Verdicts.
    progress("Computing reachability")
    for advisory, package, symbols, confidence in advisories:
        result.findings.append(assess(
            graph, advisory, symbols, confidence,
            package=package.raw_name,
            installed_version=advisory.installed_version,
            top_levels=package.top_levels,
            safe_wrappers=safe_wrappers_for(advisory.id, advisory.aliases, curated),
            max_depth=max_depth,
        ))

    result.findings.sort(key=lambda f: f.sort_key)
    result.stats = {
        "packages": len(packages),
        "advisories": len(result.findings),
        "files": len(iter_python_files(target)),
        "dependency_modules": len(dependency_modules),
        "symbols_curated": curated_count,
        "symbols_derived": derived_count,
        "reachable": sum(1 for f in result.findings if f.reachability is Reachability.REACHABLE),
        "possible": sum(1 for f in result.findings if f.reachability is Reachability.POSSIBLE),
        "unknown": sum(1 for f in result.findings if f.reachability is Reachability.UNKNOWN),
        "not_reachable": sum(1 for f in result.findings if f.reachability is Reachability.NOT_REACHABLE),
        **graph.stats(),
    }
    return result


def _deduplicate(entries: list) -> list:
    """Collapse records that describe the same CVE.

    OSV happily returns a GHSA record *and* a PYSEC record for one
    vulnerability. Reporting both doubles the noise this tool exists to
    remove, so we keep the richest copy of each: the one that actually has
    symbols, then a real severity, then a summary.
    """
    best: dict[str, tuple] = {}
    order: list[str] = []

    for entry in entries:
        advisory, package, symbols, confidence = entry
        key = f"{normalise(package.name)}::{advisory.cve}"
        if key not in best:
            best[key] = entry
            order.append(key)
            continue

        if _richness(entry) > _richness(best[key]):
            # Keep any aliases the discarded record contributed.
            merged = set(best[key][0].aliases) | set(advisory.aliases)
            advisory.aliases = sorted(merged)
            best[key] = entry
        else:
            kept = best[key][0]
            kept.aliases = sorted(set(kept.aliases) | set(advisory.aliases))

    return [best[key] for key in order]


def _richness(entry) -> tuple:
    advisory, _package, symbols, confidence = entry
    return (
        1 if symbols else 0,
        {Confidence.CURATED: 2, Confidence.DERIVED: 1, Confidence.NONE: 0}[confidence],
        0 if (advisory.severity or "UNKNOWN") == "UNKNOWN" else 1,
        1 if advisory.id.startswith("GHSA") else 0,
        1 if advisory.summary else 0,
        1 if advisory.fixed_versions else 0,
    )
