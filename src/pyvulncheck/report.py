"""Render findings as text, JSON, or SARIF.

The text report is the product. Everything else in this package exists to
make four lines like these truthful:

    jinja2 3.1.2 -> 3.1.3   CVE-2024-22195  MODERATE
      app/views.py:6
      render_attrs -> jinja2.filters.do_xmlattr
"""

from __future__ import annotations

import json
import os
import sys
from typing import Iterable, Optional, TextIO

from pyvulncheck.models import Confidence, Finding, Reachability

ARROW = " \u2192 "

_COLOURS = {
    Reachability.REACHABLE: "\033[1;31m",      # bold red
    Reachability.POSSIBLE: "\033[1;33m",       # bold yellow
    Reachability.UNKNOWN: "\033[0;36m",        # cyan
    Reachability.NOT_REACHABLE: "\033[0;32m",  # green
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

_LABELS = {
    Reachability.REACHABLE: "REACHABLE",
    Reachability.POSSIBLE: "POSSIBLE",
    Reachability.NOT_REACHABLE: "not reachable",
    Reachability.UNKNOWN: "UNKNOWN",
}


def use_colour(stream: TextIO, override: Optional[bool] = None) -> bool:
    if override is not None:
        return override
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


class _Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if self.enabled else text

    def verdict(self, reachability: Reachability) -> str:
        return self(_LABELS[reachability], _COLOURS[reachability])

    def dim(self, text: str) -> str:
        return self(text, _DIM)

    def bold(self, text: str) -> str:
        return self(text, _BOLD)


def _relative(path: Optional[str]) -> str:
    if not path:
        return ""
    try:
        return os.path.relpath(path)
    except (ValueError, OSError):
        return path


def render_text(
    findings: Iterable[Finding],
    *,
    colour: bool = False,
    show_all: bool = False,
    stats: Optional[dict] = None,
    scanned: Optional[dict] = None,
) -> str:
    paint = _Painter(colour)
    findings = sorted(findings, key=lambda f: f.sort_key)
    lines: list[str] = []

    buckets: dict[Reachability, list[Finding]] = {r: [] for r in Reachability}
    for finding in findings:
        buckets[finding.reachability].append(finding)

    total = len(findings)
    actionable = len(buckets[Reachability.REACHABLE]) + len(buckets[Reachability.POSSIBLE])

    if scanned:
        lines.append(paint.dim(
            f"Scanned {scanned.get('files', 0)} files, "
            f"{scanned.get('packages', 0)} installed packages, "
            f"{scanned.get('advisories', 0)} advisories."
        ))
        lines.append("")

    if not total:
        lines.append(paint("No known vulnerabilities in the installed packages.", _COLOURS[Reachability.NOT_REACHABLE]))
        return "\n".join(lines)

    order = [Reachability.REACHABLE, Reachability.POSSIBLE, Reachability.UNKNOWN]
    if show_all:
        order.append(Reachability.NOT_REACHABLE)

    for reachability in order:
        group = buckets[reachability]
        if not group:
            continue
        heading = {
            Reachability.REACHABLE: "Vulnerabilities your code can reach",
            Reachability.POSSIBLE: "Possibly reachable (receiver could not be resolved)",
            Reachability.UNKNOWN: "No symbol data - reachability unknown",
            Reachability.NOT_REACHABLE: "No call path found",
        }[reachability]
        lines.append(paint.bold(f"{heading} ({len(group)})"))
        lines.append("")
        for finding in group:
            lines.extend(_render_finding(finding, paint))
        lines.append("")

    hidden = len(buckets[Reachability.NOT_REACHABLE])
    summary = (
        f"{total} advisor{'y' if total == 1 else 'ies'} affect installed packages. "
        f"{actionable} need attention."
    )
    lines.append(paint.bold(summary))
    if hidden and not show_all:
        lines.append(paint.dim(
            f"{hidden} had no reachable call path and were hidden (use --all to list them)."
        ))
    if buckets[Reachability.NOT_REACHABLE]:
        lines.append(paint.dim(
            "'No call path found' is not a proof of safety - see the Limitations "
            "section of the README."
        ))
    return "\n".join(lines)


def _render_finding(finding: Finding, paint: _Painter) -> list[str]:
    advisory = finding.advisory
    fix = f" \u2192 {advisory.fix_hint}" if advisory.fix_hint else ""
    header = (
        f"  {paint.verdict(finding.reachability)}  "
        f"{paint.bold(finding.package)} {finding.installed_version}{fix}  "
        f"{advisory.cve}  {advisory.severity}"
    )
    lines = [header]

    if advisory.summary:
        lines.append(f"    {paint.dim(advisory.summary[:100])}")

    if finding.confidence is Confidence.DERIVED:
        lines.append(f"    {paint.dim('symbols derived from the fix commit')}")
    elif finding.confidence is Confidence.CURATED:
        lines.append(f"    {paint.dim('symbols from the curated dataset')}")

    for path in finding.paths[:3]:
        location = _relative(path.entry_file)
        if location and path.entry_line:
            lines.append(f"    {location}:{path.entry_line}")
        lines.append(f"      {ARROW.join(path.nodes)}")

    for caller in finding.possible_callers[:3]:
        lines.append(f"    {caller} {paint.dim('(unresolved receiver)')}")

    if not finding.paths and not finding.possible_callers and finding.reason:
        lines.append(f"    {paint.dim(finding.reason)}")

    lines.append("")
    return lines


def render_json(findings: Iterable[Finding], *, stats: Optional[dict] = None) -> str:
    findings = sorted(findings, key=lambda f: f.sort_key)
    counts: dict[str, int] = {}
    for finding in findings:
        key = finding.reachability.value
        counts[key] = counts.get(key, 0) + 1
    payload = {
        "tool": "pyvulncheck",
        "version": _version(),
        "summary": {
            "total": len(findings),
            "actionable": sum(1 for f in findings if f.actionable),
            "by_reachability": counts,
        },
        "stats": stats or {},
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def render_sarif(findings: Iterable[Finding]) -> str:
    """SARIF 2.1.0 so GitHub code scanning can ingest the results."""
    findings = sorted(findings, key=lambda f: f.sort_key)
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in findings:
        if not finding.actionable:
            continue
        advisory = finding.advisory
        rule_id = advisory.id
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"Reachable{advisory.package.title().replace('-', '')}Vulnerability",
                "shortDescription": {"text": advisory.summary or rule_id},
                "fullDescription": {"text": (advisory.details or advisory.summary or rule_id)[:1000]},
                "helpUri": f"https://osv.dev/vulnerability/{rule_id}",
                "properties": {
                    "security-severity": _sarif_severity(advisory.severity),
                    "tags": ["security", "vulnerability", "reachability"],
                },
            }

        path = finding.paths[0] if finding.paths else None
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": _sarif_uri(path.entry_file) if path else "requirements.txt"},
                "region": {"startLine": (path.entry_line if path and path.entry_line else 1)},
            }
        }
        chain = path.render(ARROW) if path else ", ".join(finding.possible_callers)
        message = (
            f"{finding.package} {finding.installed_version} is affected by {advisory.cve} "
            f"({finding.reachability.value}). {chain}"
        )
        if advisory.fix_hint:
            message += f" Fixed in {advisory.fix_hint}."
        results.append({
            "ruleId": rule_id,
            "level": "error" if finding.reachability is Reachability.REACHABLE else "warning",
            "message": {"text": message},
            "locations": [location],
        })

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pyvulncheck",
                "version": _version(),
                "informationUri": "https://github.com/ashflamer/pyvulncheck",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }, indent=2)


def _sarif_uri(path: Optional[str]) -> str:
    return _relative(path).replace(os.sep, "/") if path else "requirements.txt"


def _sarif_severity(severity: str) -> str:
    return {
        "CRITICAL": "9.0", "HIGH": "7.5", "MODERATE": "5.0",
        "MEDIUM": "5.0", "LOW": "3.0",
    }.get((severity or "").upper(), "5.0")


def _version() -> str:
    try:
        from pyvulncheck import __version__

        return __version__
    except Exception:
        return "0.0.0"


def exit_code(findings: Iterable[Finding], *, fail_on: str = "reachable") -> int:
    """CI contract: 1 when something at or above `fail_on` was found."""
    thresholds = {
        "reachable": {Reachability.REACHABLE},
        "possible": {Reachability.REACHABLE, Reachability.POSSIBLE},
        "unknown": {Reachability.REACHABLE, Reachability.POSSIBLE, Reachability.UNKNOWN},
        "any": set(Reachability),
        "never": set(),
    }
    trigger = thresholds.get(fail_on, thresholds["reachable"])
    return 1 if any(f.reachability in trigger for f in findings) else 0
