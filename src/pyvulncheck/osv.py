"""Minimal OSV.dev client. Stdlib only, with an on-disk cache."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Optional

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"

DEFAULT_TTL = 24 * 3600  # advisories don't change minute to minute
USER_AGENT = "pyvulncheck (+https://github.com/ashflamer/pyvulncheck)"


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "pyvulncheck"


class OfflineError(RuntimeError):
    """Raised when the network is needed but --offline was requested."""


class OSVClient:
    """Queries OSV.dev, caching every response on disk.

    The cache matters for more than speed: it means CI runs are reproducible
    and a flaky network doesn't turn into a failed security gate.
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        *,
        ttl: int = DEFAULT_TTL,
        offline: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else default_cache_dir()
        self.ttl = ttl
        self.offline = offline
        self.timeout = timeout
        self._memo: dict[str, Any] = {}

    # ---------------------------------------------------------------- cache

    def _cache_path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()[:20]
        return self.cache_dir / f"{digest}.json"

    def _read_cache(self, key: str) -> Optional[Any]:
        if key in self._memo:
            return self._memo[key]
        path = self._cache_path(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        # ttl < 0 means never expire; ttl == 0 means always refetch.
        if self.ttl >= 0 and time.time() - payload.get("_fetched_at", 0) > self.ttl:
            return None
        value = payload.get("data")
        self._memo[key] = value
        return value

    def _write_cache(self, key: str, data: Any) -> None:
        self._memo[key] = data
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._cache_path(key).write_text(
                json.dumps({"_fetched_at": time.time(), "data": data}),
                encoding="utf-8",
            )
        except OSError:  # a broken cache must never break a scan
            pass

    # ------------------------------------------------------------- requests

    def _post(self, url: str, body: dict) -> Any:
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode())

    def _get(self, url: str) -> Any:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode())

    # ------------------------------------------------------------------ api

    def query_batch(self, packages: Iterable[tuple[str, str]]) -> dict[tuple[str, str], list[str]]:
        """Map (package, version) -> [advisory ids].

        Uses OSV's querybatch, which returns ids only; details are fetched
        separately (and cached) so repeat runs are nearly free.
        """
        packages = list(packages)
        if not packages:
            return {}

        results: dict[tuple[str, str], list[str]] = {}
        pending: list[tuple[str, str]] = []

        for name, version in packages:
            cached = self._read_cache(f"q:{name}:{version}")
            if cached is not None:
                results[(name, version)] = cached
            else:
                pending.append((name, version))

        # OSV caps batch size; chunk to stay well under it.
        for chunk in _chunks(pending, 100):
            body = {
                "queries": [
                    {"package": {"name": n, "ecosystem": "PyPI"}, "version": v}
                    for n, v in chunk
                ]
            }
            if self.offline:
                raise OfflineError("advisory data not cached and --offline was set")
            try:
                payload = self._post(OSV_QUERYBATCH, body)
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                raise ConnectionError(f"OSV query failed: {exc}") from exc

            for (name, version), entry in zip(chunk, payload.get("results", [])):
                ids = [v["id"] for v in entry.get("vulns", []) if "id" in v]
                results[(name, version)] = ids
                self._write_cache(f"q:{name}:{version}", ids)

        return results

    def get_vuln(self, vuln_id: str) -> Optional[dict]:
        """Fetch the full advisory record."""
        cached = self._read_cache(f"v:{vuln_id}")
        if cached is not None:
            return cached
        if self.offline:
            raise OfflineError(f"advisory {vuln_id} not cached and --offline was set")
        try:
            data = self._get(OSV_VULN + vuln_id)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise ConnectionError(f"OSV lookup failed for {vuln_id}: {exc}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ConnectionError(f"OSV lookup failed for {vuln_id}: {exc}") from exc
        self._write_cache(f"v:{vuln_id}", data)
        return data


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


# --------------------------------------------------------------- parsing


def severity_of(record: dict) -> str:
    """Pull a human severity out of an OSV record.

    OSV stores severity in several places depending on the source database;
    GHSA records put a word in database_specific, CVSS vectors live elsewhere.
    """
    db = record.get("database_specific") or {}
    if isinstance(db, dict):
        sev = db.get("severity")
        if isinstance(sev, str) and sev:
            return sev.upper()

    for entry in record.get("severity") or []:
        score = entry.get("score", "")
        if isinstance(score, str) and score.startswith("CVSS:"):
            return _cvss_band(score)

    for affected in record.get("affected") or []:
        db = affected.get("database_specific") or {}
        if isinstance(db, dict) and isinstance(db.get("severity"), str):
            return db["severity"].upper()

    return "UNKNOWN"


def _cvss_band(vector: str) -> str:
    """Very rough CVSS v3 base-score banding from the vector string.

    We only need a label for sorting, not an exact score, so this reads the
    few metrics that dominate the base score rather than implementing the
    full specification.
    """
    parts = dict(
        piece.split(":", 1) for piece in vector.split("/") if ":" in piece
    )
    impact = sum(
        1 for key in ("C", "I", "A") if parts.get(key) in ("H",)
    )
    if impact >= 2 and parts.get("AV") == "N" and parts.get("PR") == "N":
        return "CRITICAL"
    if impact >= 1 and parts.get("AV") == "N":
        return "HIGH"
    if impact >= 1:
        return "MODERATE"
    return "LOW"


def fixed_versions_of(record: dict, package: str) -> list[str]:
    """Find the versions that contain the fix."""
    out: list[str] = []
    for affected in record.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name", "")
        if _normalise(pkg) != _normalise(package):
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    out.append(event["fixed"])
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(out))


def fix_commits_of(record: dict) -> list[str]:
    """Collect links that look like the commit which fixed the issue.

    This is the key input for symbol derivation: PyPI advisories have no
    symbol data, but they almost always reference the fixing commit.
    """
    commits: list[str] = []

    for affected in record.get("affected") or []:
        for rng in affected.get("ranges") or []:
            if rng.get("type") != "GIT":
                continue
            repo = rng.get("repo", "")
            for event in rng.get("events") or []:
                if "fixed" in event and repo:
                    commits.append(f"{repo}/commit/{event['fixed']}")

    for ref in record.get("references") or []:
        url = ref.get("url", "")
        if "/commit/" in url and "github.com" in url:
            commits.append(url)
        elif "/pull/" in url and "github.com" in url:
            commits.append(url)

    return list(dict.fromkeys(commits))


def _normalise(name: str) -> str:
    """PEP 503 normalisation: Foo.Bar_baz and foo-bar-baz are the same project."""
    import re

    return re.sub(r"[-_.]+", "-", name).lower()
