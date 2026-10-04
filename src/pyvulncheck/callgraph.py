"""Build a call graph from Python source with the ast module.

Python is dynamically typed, so a *sound* call graph is impossible: anything
can be rebound at runtime. This builder is deliberately a best-effort
approximation that is honest about what it could not resolve, splitting call
sites into two buckets:

  edges   - the callee was resolved to a fully qualified name
  dynamic - a method call whose receiver could not be resolved

The second bucket is what produces POSSIBLE verdicts instead of silently
claiming safety. Pretending otherwise would be the one unforgivable bug in a
security tool.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env", ".env",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "node_modules", "build", "dist", ".eggs", "site-packages",
}


@dataclass
class Definition:
    qualname: str
    module: str
    file: Path
    line: int
    is_first_party: bool = True

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class CallGraph:
    definitions: dict[str, Definition] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=dict)
    dynamic: dict[str, set[str]] = field(default_factory=dict)
    imported_modules: set[str] = field(default_factory=set)
    first_party_modules: set[str] = field(default_factory=set)
    module_level: dict[str, set[str]] = field(default_factory=dict)
    """Calls made at import time (module body), keyed by module name."""

    def add_edge(self, caller: str, callee: str) -> None:
        self.edges.setdefault(caller, set()).add(callee)

    def add_dynamic(self, caller: str, method: str) -> None:
        self.dynamic.setdefault(caller, set()).add(method)

    @property
    def first_party_definitions(self) -> list[Definition]:
        return [d for d in self.definitions.values() if d.is_first_party]

    def stats(self) -> dict:
        return {
            "definitions": len(self.definitions),
            "first_party_definitions": len(self.first_party_definitions),
            "edges": sum(len(v) for v in self.edges.values()),
            "dynamic_calls": sum(len(v) for v in self.dynamic.values()),
            "modules_imported": len(self.imported_modules),
        }


# --------------------------------------------------------------- discovery


def iter_python_files(root: Path, *, skip: Iterable[str] = SKIP_DIRS) -> list[Path]:
    skip = set(skip)
    root = Path(root)
    if root.is_file():
        return [root] if root.suffix == ".py" else []

    out: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name in skip or entry.name.startswith("."):
                    continue
                stack.append(entry)
            elif entry.suffix == ".py":
                out.append(entry)
    return sorted(out)


def module_name_for(path: Path, root: Path) -> str:
    """Derive a dotted module name for a file inside `root`."""
    try:
        relative = path.resolve().relative_to(Path(root).resolve())
    except ValueError:
        relative = Path(path.name)

    parts = list(relative.parts)
    if parts and parts[-1].endswith(".py"):
        parts[-1] = parts[-1][: -len(".py")]
    if parts and parts[-1] == "__init__":
        parts.pop()
    while parts and parts[0] in {"src", "lib"}:
        parts.pop(0)
    return ".".join(parts)


# ----------------------------------------------------------------- visitor


class _ModuleVisitor(ast.NodeVisitor):
    """Walks one module, recording definitions and call edges."""

    def __init__(self, graph: CallGraph, module: str, file: Path, first_party: bool) -> None:
        self.graph = graph
        self.module = module
        self.file = file
        self.first_party = first_party
        # local name -> fully qualified name it refers to
        self.aliases: dict[str, str] = {}
        self.scope: list[str] = []
        self.class_stack: list[str] = []

    # ------------------------------------------------------------ imports

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            target = alias.name
            local = alias.asname or alias.name.split(".")[0]
            # `import a.b.c` binds `a`, but `import a.b.c as x` binds x -> a.b.c
            self.aliases[local] = target if alias.asname else alias.name.split(".")[0]
            self.graph.imported_modules.add(target)
            self.graph.imported_modules.add(target.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if node.level:  # relative import
            base = self.module.split(".") if self.module else []
            # Inside a package's __init__.py, `.` means that package itself;
            # inside a plain module it means the package containing it.
            if self.file.name == "__init__.py":
                base = [*base, "__placeholder__"]
            trimmed = base[: max(0, len(base) - node.level)]
            module = ".".join([*trimmed, module]) if module else ".".join(trimmed)
        if module:
            self.graph.imported_modules.add(module)
            self.graph.imported_modules.add(module.split(".")[0])
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            self.aliases[local] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    # -------------------------------------------------------- definitions

    def _enter_function(self, node) -> str:
        name = node.name
        qualname = ".".join([self.module, *self.scope, name]) if self.module else ".".join([*self.scope, name])
        self.graph.definitions[qualname] = Definition(
            qualname=qualname, module=self.module, file=self.file,
            line=node.lineno, is_first_party=self.first_party,
        )
        return qualname

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        qualname = self._enter_function(node)
        self.scope.append(node.name)
        self._walk_body(node, qualname)
        self.scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        qualname = self._enter_function(node)
        self.scope.append(node.name)
        self._walk_body(node, qualname)
        self.scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualname = ".".join([self.module, *self.scope, node.name]) if self.module else node.name
        self.graph.definitions[qualname] = Definition(
            qualname=qualname, module=self.module, file=self.file,
            line=node.lineno, is_first_party=self.first_party,
        )
        # Base classes are a form of dependency on the parent's API.
        for base in node.bases:
            resolved = self._resolve(base)
            if resolved:
                self.graph.add_edge(qualname, resolved)

        self.scope.append(node.name)
        self.class_stack.append(qualname)
        for child in node.body:
            self.visit(child)
        self.class_stack.pop()
        self.scope.pop()

    def _walk_body(self, node, owner: str) -> None:
        """Record every call inside a function body, attributed to `owner`."""
        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if child is not node:
                    continue  # nested defs are visited separately
            if isinstance(child, ast.Call):
                self._record_call(child, owner)
        # Visit nested definitions so they get their own entries.
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.visit(child)

    # -------------------------------------------------------------- calls

    def _record_call(self, node: ast.Call, owner: str) -> None:
        resolved = self._resolve(node.func)
        if resolved:
            self.graph.add_edge(owner, resolved)
            return
        # Unresolved: keep the attribute name so we can still flag a
        # name-level match later.
        if isinstance(node.func, ast.Attribute):
            self.graph.add_dynamic(owner, node.func.attr)
        elif isinstance(node.func, ast.Name):
            self.graph.add_dynamic(owner, node.func.id)

    def _resolve(self, node: ast.AST) -> Optional[str]:
        """Resolve a call target to a fully qualified name, if we can."""
        parts = _attribute_chain(node)
        if not parts:
            return None

        head, *rest = parts

        if head in {"self", "cls"} and self.class_stack:
            if rest:
                return f"{self.class_stack[-1]}.{'.'.join(rest)}"
            return None

        if head in self.aliases:
            base = self.aliases[head]
            return ".".join([base, *rest]) if rest else base

        # A name defined in this module.
        local = f"{self.module}.{head}" if self.module else head
        if local in self.graph.definitions:
            return ".".join([local, *rest]) if rest else local

        return None

    # Module-level code runs on import, so it is always reachable.
    def visit_Module(self, node: ast.Module) -> None:
        owner = f"{self.module}:<module>"
        self.graph.definitions[owner] = Definition(
            qualname=owner, module=self.module, file=self.file,
            line=1, is_first_party=self.first_party,
        )
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.visit(child)
            else:
                for sub in ast.walk(child):
                    if isinstance(sub, ast.Call):
                        self._record_call(sub, owner)
                self.visit(child)


def _attribute_chain(node: ast.AST) -> list[str]:
    """`a.b.c(...)` -> ['a','b','c']; returns [] for anything dynamic."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return list(reversed(parts))
    return []


# ------------------------------------------------------------------ build


def analyse_source(
    graph: CallGraph, source: str, module: str, file: Path, *, first_party: bool = True
) -> None:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return  # a file we can't parse is simply not analysed
    if first_party and module:
        graph.first_party_modules.add(module)
    visitor = _ModuleVisitor(graph, module, file, first_party)
    visitor.visit(tree)


def build_call_graph(
    roots: Iterable[Path],
    *,
    dependency_modules: Optional[dict[str, Path]] = None,
    max_files: int = 20_000,
) -> CallGraph:
    """Build a graph over first-party roots plus selected dependency modules.

    `dependency_modules` maps a dotted module name to its source file. Only the
    packages that actually carry advisories get parsed, which keeps a scan of a
    large virtualenv to a second or two instead of a minute.
    """
    graph = CallGraph()

    count = 0
    for root in roots:
        root = Path(root)
        # When the target is one file, names are relative to its directory.
        base = root.parent if root.is_file() else root
        for file in iter_python_files(root):
            if count >= max_files:
                break
            count += 1
            try:
                source = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            analyse_source(graph, source, module_name_for(file, base), file, first_party=True)

    for module, file in (dependency_modules or {}).items():
        try:
            source = Path(file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        analyse_source(graph, source, module, Path(file), first_party=False)

    return graph
