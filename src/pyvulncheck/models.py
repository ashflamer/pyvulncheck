"""Core data types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Reachability(str, Enum):
    """How confident are we that this vulnerability can actually be triggered?"""

    REACHABLE = "REACHABLE"
    """A concrete, resolved call path exists from your code to the vulnerable symbol."""

    POSSIBLE = "POSSIBLE"
    """You call a method with a matching name, but the receiver could not be
    resolved statically (duck typing, a factory, a dynamic attribute). Python
    is not statically typed; this is the honest middle ground."""

    NOT_REACHABLE = "NOT_REACHABLE"
    """No static path found. NOT a proof of safety - see the caveats in the README."""

    UNKNOWN = "UNKNOWN"
    """No symbol data could be resolved for this advisory, so reachability
    could not be assessed. Falls back to 'is the package imported at all'."""

    @property
    def rank(self) -> int:
        """Sort priority, most urgent first. 0 sorts to the top of a report."""
        return {"REACHABLE": 0, "POSSIBLE": 1, "UNKNOWN": 2, "NOT_REACHABLE": 3}[self.value]

    @property
    def actionable(self) -> bool:
        """Does a human need to look at this?

        UNKNOWN is excluded on purpose: it means the tool lacks symbol data,
        which is a gap in *our* dataset rather than a finding about the user's
        code. It is still displayed in its own section so nobody mistakes it
        for a clean result.
        """
        return self in (Reachability.REACHABLE, Reachability.POSSIBLE)


class Confidence(str, Enum):
    """Where the vulnerable-symbol list came from."""

    CURATED = "curated"
    """Hand-reviewed entry in this project's advisory dataset. Highest trust."""

    DERIVED = "derived"
    """Extracted automatically from the advisory's fix commit."""

    NONE = "none"
    """No symbol data available."""


@dataclass(frozen=True)
class VulnerableSymbol:
    """A fully-qualified Python symbol that carries the vulnerability.

    e.g. module="jinja2.filters", name="do_xmlattr"
    """

    module: str
    name: str

    @property
    def qualname(self) -> str:
        return f"{self.module}.{self.name}" if self.module else self.name

    @property
    def leaf(self) -> str:
        """Last path component - used for duck-typed method matching."""
        return self.name.rsplit(".", 1)[-1]

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.qualname


@dataclass
class Advisory:
    """One OSV advisory affecting one installed package."""

    id: str
    package: str
    installed_version: str
    summary: str = ""
    details: str = ""
    aliases: list[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    fixed_versions: list[str] = field(default_factory=list)
    fix_commits: list[str] = field(default_factory=list)
    symbols: list[VulnerableSymbol] = field(default_factory=list)
    symbol_confidence: Confidence = Confidence.NONE

    @property
    def cve(self) -> str:
        """Prefer the CVE id when one exists - it's what people search for."""
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        return self.id

    @property
    def fix_hint(self) -> Optional[str]:
        return self.fixed_versions[0] if self.fixed_versions else None


@dataclass
class CallPath:
    """A resolved chain: your code -> ... -> the vulnerable symbol.

    `nodes` is ordered from the entry point in first-party code to the
    vulnerable function, which is the direction a human reads it.
    """

    nodes: list[str] = field(default_factory=list)
    entry_file: Optional[str] = None
    entry_line: Optional[int] = None

    def __len__(self) -> int:
        return len(self.nodes)

    @property
    def length(self) -> int:
        return len(self.nodes)

    @property
    def entry(self) -> str:
        return self.nodes[0] if self.nodes else ""

    @property
    def target(self) -> str:
        return self.nodes[-1] if self.nodes else ""

    @property
    def location(self) -> str:
        if self.entry_file and self.entry_line:
            return f"{self.entry_file}:{self.entry_line}"
        return self.entry_file or ""

    def render(self, arrow: str = " \u2192 ") -> str:
        return arrow.join(self.nodes)

    def to_dict(self) -> dict:
        return {
            "nodes": list(self.nodes),
            "entry": self.entry,
            "target": self.target,
            "file": self.entry_file,
            "line": self.entry_line,
            "length": self.length,
        }


@dataclass
class Finding:
    """An advisory plus the reachability verdict for this codebase."""

    advisory: Advisory
    package: str = ""
    installed_version: str = ""
    reachability: Reachability = Reachability.UNKNOWN
    symbols: list[VulnerableSymbol] = field(default_factory=list)
    matched_symbols: list[VulnerableSymbol] = field(default_factory=list)
    paths: list[CallPath] = field(default_factory=list)
    possible_callers: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.NONE
    imported: bool = False
    reason: str = ""

    @property
    def actionable(self) -> bool:
        return self.reachability.actionable

    @property
    def sort_key(self) -> tuple:
        """Most urgent first: verdict, then severity, then package name."""
        severity_rank = {
            "CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2,
            "LOW": 3, "": 4, None: 4,
        }
        return (
            self.reachability.rank,
            severity_rank.get((self.advisory.severity or "").upper(), 4),
            self.package,
            self.advisory.id,
        )

    def to_dict(self) -> dict:
        return {
            "id": self.advisory.id,
            "cve": self.advisory.cve,
            "aliases": list(self.advisory.aliases),
            "package": self.package or self.advisory.package,
            "installed_version": self.installed_version,
            "fixed_version": self.advisory.fix_hint,
            "severity": self.advisory.severity,
            "summary": self.advisory.summary,
            "reachability": self.reachability.value,
            "actionable": self.actionable,
            "symbol_confidence": self.confidence.value,
            "imported": self.imported,
            "reason": self.reason,
            "vulnerable_symbols": [s.qualname for s in self.symbols],
            "matched_symbols": [s.qualname for s in self.matched_symbols],
            "possible_callers": list(self.possible_callers),
            "paths": [p.to_dict() for p in self.paths],
        }
