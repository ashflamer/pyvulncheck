"""Decide whether a vulnerable function can actually be called.

The analysis runs *backwards*. Forward BFS from every function in a codebase
explores an enormous space to mostly prove nothing; walking the reverse edges
out from each vulnerable symbol touches only the subgraph that matters, and
the predecessor map it builds hands back a ready-made call path for free.
"""

from __future__ import annotations

from collections import deque
from typing import Iterable, Optional

from pyvulncheck.callgraph import CallGraph
from pyvulncheck.models import (
    Advisory, CallPath, Confidence, Finding, Reachability, VulnerableSymbol,
)

MAX_DEPTH = 12


def _reverse_edges(graph: CallGraph) -> dict[str, set[str]]:
    reverse: dict[str, set[str]] = {}
    for caller, callees in graph.edges.items():
        for callee in callees:
            reverse.setdefault(callee, set()).add(caller)
    return reverse


def _candidate_targets(graph: CallGraph, symbol: VulnerableSymbol) -> set[str]:
    """Call-graph nodes that plausibly mean 'this symbol'.

    Exact match is the common case. Re-exports are the awkward one: code
    written as `from jinja2 import do_xmlattr` resolves to `jinja2.do_xmlattr`
    while the advisory names `jinja2.filters.do_xmlattr`. Same function, two
    spellings - so a match on the leaf name within the same top-level package
    counts too.
    """
    wanted = symbol.qualname
    leaf = symbol.leaf
    top = symbol.module.split(".")[0] if symbol.module else ""

    targets: set[str] = set()
    for node in set(graph.edges) | {c for v in graph.edges.values() for c in v}:
        if node == wanted:
            targets.add(node)
            continue
        if not top or not node.startswith(top + "."):
            continue
        if node.split(".")[-1] == leaf:
            targets.add(node)
        elif "." in leaf and node.endswith("." + leaf):
            targets.add(node)  # Class.method named in full
    return targets


def _is_entry_point(node: str, graph: CallGraph, reverse: dict[str, set[str]]) -> bool:
    """A function nothing else in the project calls - i.e. where control enters."""
    definition = graph.definitions.get(node)
    if definition is None or not definition.is_first_party:
        return False
    if node.endswith(":<module>"):
        return True
    callers = [c for c in reverse.get(node, set())
               if (d := graph.definitions.get(c)) and d.is_first_party]
    return not callers


def find_paths(
    graph: CallGraph, symbol: VulnerableSymbol, *, max_depth: int = MAX_DEPTH, max_paths: int = 3
) -> list[CallPath]:
    """Shortest call paths from first-party code to `symbol`."""
    reverse = _reverse_edges(graph)
    targets = _candidate_targets(graph, symbol)
    if not targets:
        return []

    paths: list[CallPath] = []
    seen_starts: set[str] = set()

    for target in sorted(targets):
        # BFS outwards along reverse edges; first time we touch a first-party
        # node is the shortest path to it.
        previous: dict[str, Optional[str]] = {target: None}
        queue = deque([(target, 0)])
        hits: list[str] = []

        while queue:
            node, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for caller in sorted(reverse.get(node, set())):
                if caller in previous:
                    continue
                previous[caller] = node
                definition = graph.definitions.get(caller)
                if definition and definition.is_first_party:
                    hits.append(caller)
                queue.append((caller, depth + 1))

        # Prefer true entry points, then the shortest chain.
        def rank(node: str) -> tuple:
            length = 0
            cursor: Optional[str] = node
            while cursor is not None:
                cursor = previous[cursor]
                length += 1
            return (0 if _is_entry_point(node, graph, reverse) else 1, length)

        for start in sorted(hits, key=rank):
            if start in seen_starts:
                continue
            seen_starts.add(start)

            nodes: list[str] = []
            cursor: Optional[str] = start
            while cursor is not None:
                nodes.append(cursor)
                cursor = previous[cursor]

            definition = graph.definitions.get(start)
            paths.append(CallPath(
                nodes=nodes,
                entry_file=str(definition.file) if definition else None,
                entry_line=definition.line if definition else None,
            ))
            if len(paths) >= max_paths:
                return paths

    return paths


def _entry_into_package(path: CallPath, top_levels: Iterable[str]) -> Optional[str]:
    """The first node on `path` that belongs to the vulnerable package.

    A call path crosses from your code into a dependency at exactly one point.
    *Where* it crosses changes what the path means.
    """
    tops = {t for t in top_levels if t}
    for node in path.nodes:
        head = node.split(".")[0].split(":")[0]
        if head in tops:
            return node
    return None


def _classify_path(
    path: CallPath, symbol: VulnerableSymbol, top_levels: Iterable[str],
    safe_wrappers: set,
) -> str:
    """direct | wrapped | indirect.

    The distinction that stops the most common false positive in Python.

    `yaml.safe_load()` calls `yaml.load()` internally, so a naive graph walk
    "proves" that every project using safe_load reaches the vulnerable
    `yaml.load` - which is backwards, since safe_load is the documented fix.
    The advisory's symbol list describes a *public API boundary*: what matters
    is the function your code calls to enter the package, not how the package
    routes internally afterwards.
    """
    entry = _entry_into_package(path, top_levels)
    if entry is None or entry == path.target:
        return "direct"
    if entry in safe_wrappers or entry.split(".")[-1] in {w.split(".")[-1] for w in safe_wrappers}:
        return "wrapped"
    return "indirect"


def _possible_hits(graph: CallGraph, symbol: VulnerableSymbol) -> list[str]:
    """Callers that invoke a matching *method name* on an unresolved receiver.

    `handler.render(x)` where `handler` came out of a factory, a registry, or
    a plugin. We cannot prove it is the vulnerable class; we certainly cannot
    prove it isn't. That is what POSSIBLE means.
    """
    leaf = symbol.leaf.split(".")[-1]
    out = []
    for caller, methods in graph.dynamic.items():
        if leaf in methods:
            definition = graph.definitions.get(caller)
            if definition and definition.is_first_party:
                out.append(caller)
    return sorted(out)


def _package_is_imported(graph: CallGraph, top_levels: Iterable[str]) -> bool:
    imported = graph.imported_modules
    return any(top in imported for top in top_levels)


def assess(
    graph: CallGraph,
    advisory: Advisory,
    symbols: list[VulnerableSymbol],
    confidence: Confidence,
    *,
    package: str,
    installed_version: str,
    top_levels: Iterable[str] = (),
    safe_wrappers: Iterable[str] = (),
    max_depth: int = MAX_DEPTH,
) -> Finding:
    """Produce the verdict for one advisory against one codebase."""
    top_levels = list(top_levels) or [package.replace("-", "_")]
    imported = _package_is_imported(graph, top_levels)

    finding = Finding(
        advisory=advisory,
        package=package,
        installed_version=installed_version,
        symbols=symbols,
        confidence=confidence,
        imported=imported,
    )

    # No symbol data at all: we know the package is vulnerable, and nothing
    # more. Saying NOT_REACHABLE here would be a lie dressed as a result.
    if not symbols:
        finding.reachability = Reachability.UNKNOWN if imported else Reachability.NOT_REACHABLE
        finding.reason = (
            "no vulnerable-symbol data for this advisory; package is imported"
            if imported else
            "no vulnerable-symbol data, and the package is never imported"
        )
        return finding

    if not imported:
        finding.reachability = Reachability.NOT_REACHABLE
        finding.reason = f"{package} is installed but never imported"
        return finding

    direct: list[CallPath] = []
    indirect: list[CallPath] = []
    wrapped: list[CallPath] = []
    matched: list[VulnerableSymbol] = []
    wrappers = set(safe_wrappers or ())

    for symbol in symbols:
        found = find_paths(graph, symbol, max_depth=max_depth)
        if not found:
            continue
        matched.append(symbol)
        for path in found:
            kind = _classify_path(path, symbol, top_levels, wrappers)
            {"direct": direct, "indirect": indirect, "wrapped": wrapped}[kind].append(path)

    # A resolved call straight to the vulnerable function.
    if direct:
        direct.sort(key=lambda p: p.length)
        finding.reachability = Reachability.REACHABLE
        finding.paths = direct[:5]
        finding.matched_symbols = matched
        finding.reason = f"call path reaches {direct[0].target}"
        return finding

    # The path only gets there through another function of the same package.
    # The wrapper may well constrain the dangerous argument, so this is a
    # question for a human rather than a verdict.
    if indirect:
        indirect.sort(key=lambda p: p.length)
        entry = _entry_into_package(indirect[0], top_levels)
        finding.reachability = Reachability.POSSIBLE
        finding.paths = indirect[:5]
        finding.matched_symbols = matched
        finding.reason = (
            f"reached only indirectly, via {entry} inside {package}; "
            "the wrapper may constrain the vulnerable argument"
        )
        return finding

    possible: list[str] = []
    for symbol in symbols:
        hits = _possible_hits(graph, symbol)
        if hits:
            possible.extend(hits)
            if symbol not in matched:
                matched.append(symbol)
    if possible:
        finding.reachability = Reachability.POSSIBLE
        finding.matched_symbols = matched
        finding.possible_callers = sorted(set(possible))[:5]
        finding.reason = (
            f"{len(set(possible))} call site(s) invoke a matching method name on an "
            "unresolved receiver"
        )
        return finding

    finding.reachability = Reachability.NOT_REACHABLE
    if wrapped:
        entry = _entry_into_package(wrapped[0], top_levels)
        finding.reason = (
            f"only reached through {entry}, which this advisory's curated entry "
            "records as a safe wrapper"
        )
    else:
        finding.reason = (
            f"{package} is imported, but no static call path reaches "
            f"{', '.join(s.qualname for s in symbols[:2])}"
            + ("..." if len(symbols) > 2 else "")
        )
    return finding
