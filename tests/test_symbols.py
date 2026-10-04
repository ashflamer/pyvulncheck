"""The symbol-derivation layer: the part that does not exist elsewhere."""

import json

import pytest

from pyvulncheck.models import Advisory, Confidence
from pyvulncheck.symbols import (
    PatchFetcher, _parse_qualname, curated_symbols, load_curated,
    module_from_path, parse_patch, patch_urls, resolve_symbols,
)


class TestParsePatch:
    def test_derives_the_real_jinja2_symbol(self, jinja_patch, no_network):
        """The headline claim: the vulnerable function falls out of the fix commit."""
        symbols = parse_patch(jinja_patch, top_levels=["jinja2"])
        names = {s.qualname for s in symbols}
        assert "jinja2.filters.do_xmlattr" in names

    def test_symbols_are_fully_qualified(self, jinja_patch):
        for symbol in parse_patch(jinja_patch, top_levels=["jinja2"]):
            assert symbol.module.startswith("jinja2")
            assert symbol.qualname == f"{symbol.module}.{symbol.name}"

    def test_ignores_test_files(self):
        patch = (
            "--- a/tests/test_filters.py\n"
            "+++ b/tests/test_filters.py\n"
            "@@ -1,5 +1,5 @@ def test_xmlattr(\n"
            "-    old\n"
            "+    new\n"
        )
        assert parse_patch(patch, top_levels=["jinja2"]) == []

    def test_ignores_non_python_files(self):
        patch = (
            "--- a/CHANGES.rst\n+++ b/CHANGES.rst\n"
            "@@ -1,3 +1,4 @@ def nope(\n+    note\n"
        )
        assert parse_patch(patch) == []

    def test_reads_class_context_into_method_names(self):
        patch = (
            "--- a/src/pkg/mod.py\n+++ b/src/pkg/mod.py\n"
            "@@ -10,4 +10,5 @@ class Session:\n"
            "     def send(self):\n"
            "-        old\n"
            "+        new\n"
        )
        names = {s.qualname for s in parse_patch(patch, top_levels=["pkg"])}
        assert "pkg.mod.Session" in names

    def test_picks_up_added_def_lines(self):
        patch = (
            "--- a/src/pkg/mod.py\n+++ b/src/pkg/mod.py\n"
            "@@ -1,3 +1,8 @@\n"
            "+def newly_added(value):\n"
            "+    return value\n"
        )
        names = {s.qualname for s in parse_patch(patch, top_levels=["pkg"])}
        assert "pkg.mod.newly_added" in names

    def test_skips_private_helpers(self):
        patch = (
            "--- a/src/pkg/mod.py\n+++ b/src/pkg/mod.py\n"
            "@@ -1,3 +1,4 @@ def __secret(\n+    x = 1\n"
        )
        assert parse_patch(patch, top_levels=["pkg"]) == []

    def test_dunder_methods_are_kept(self):
        patch = (
            "--- a/src/pkg/mod.py\n+++ b/src/pkg/mod.py\n"
            "@@ -1,3 +1,4 @@ def __init__(\n+    x = 1\n"
        )
        names = {s.name for s in parse_patch(patch, top_levels=["pkg"])}
        assert "__init__" in names

    def test_no_duplicate_symbols(self):
        patch = (
            "--- a/src/pkg/mod.py\n+++ b/src/pkg/mod.py\n"
            "@@ -1,3 +1,4 @@ def target(\n+    a\n"
            "@@ -20,3 +21,4 @@ def target(\n+    b\n"
        )
        symbols = parse_patch(patch, top_levels=["pkg"])
        assert len(symbols) == len({s.qualname for s in symbols})

    def test_top_level_filter_excludes_other_packages(self):
        patch = (
            "--- a/other/mod.py\n+++ b/other/mod.py\n"
            "@@ -1,3 +1,4 @@ def thing(\n+    a\n"
        )
        assert parse_patch(patch, top_levels=["jinja2"]) == []

    def test_empty_patch_is_not_an_error(self):
        assert parse_patch("") == []


class TestModuleFromPath:
    @pytest.mark.parametrize("path,expected", [
        ("src/jinja2/filters.py", "jinja2.filters"),
        ("jinja2/filters.py", "jinja2.filters"),
        ("src/pkg/__init__.py", "pkg"),
        ("src/pkg/sub/mod.py", "pkg.sub.mod"),
    ])
    def test_layouts(self, path, expected):
        assert module_from_path(path) == expected

    def test_anchors_on_known_top_level(self):
        assert module_from_path("deep/nested/jinja2/filters.py", ["jinja2"]) == "jinja2.filters"

    def test_returns_none_outside_known_package(self):
        assert module_from_path("docs/conf.py", ["jinja2"]) is None

    def test_non_python_returns_none(self):
        assert module_from_path("README.md") is None


class TestQualnameParsing:
    def test_plain_function(self):
        symbol = _parse_qualname("jinja2.filters.do_xmlattr")
        assert (symbol.module, symbol.name) == ("jinja2.filters", "do_xmlattr")

    def test_class_method_stays_together(self):
        symbol = _parse_qualname("requests.sessions.Session.rebuild_proxies")
        assert symbol.module == "requests.sessions"
        assert symbol.name == "Session.rebuild_proxies"
        assert symbol.leaf == "rebuild_proxies"

    def test_bare_name(self):
        assert _parse_qualname("thing").name == "thing"


class TestCuratedDataset:
    def test_ships_real_entries(self, curated_dir):
        assert load_curated(curated_dir), "the curated dataset should not be empty"

    def test_every_file_matches_the_schema(self, curated_dir):
        for path in curated_dir.glob("*.json"):
            record = json.loads(path.read_text())
            assert record["id"] == path.stem, f"{path.name}: id must match filename"
            assert record["schema_version"] == "1.0"
            assert record["ecosystem"] == "PyPI"
            assert record["symbols"], f"{path.name}: needs at least one symbol"
            assert record["notes"].strip(), f"{path.name}: notes are mandatory"
            for symbol in record["symbols"]:
                assert "." in symbol, f"{path.name}: {symbol} is not qualified"

    def test_lookup_by_cve_alias(self, curated_dir):
        curated = load_curated(curated_dir)
        symbols = curated_symbols("UNKNOWN-ID", ["CVE-2024-22195"], curated)
        assert symbols and symbols[0].qualname == "jinja2.filters.do_xmlattr"

    def test_lookup_is_case_insensitive(self, curated_dir):
        curated = load_curated(curated_dir)
        assert curated_symbols("ghsa-h5c8-rqwp-cp95", [], curated)

    def test_safe_load_is_not_listed_for_pyyaml(self, curated_dir):
        """The whole point: safe_load was never vulnerable."""
        curated = load_curated(curated_dir)
        symbols = curated_symbols("CVE-2020-14343", [], curated)
        assert symbols
        assert all("safe_load" not in s.qualname for s in symbols)

    def test_missing_directory_is_empty_not_fatal(self, tmp_path):
        assert load_curated(tmp_path / "nope") == {}

    def test_malformed_json_is_skipped(self, tmp_path):
        (tmp_path / "bad.json").write_text("{not json")
        (tmp_path / "good.json").write_text('{"id": "X", "symbols": ["a.b"]}')
        assert set(load_curated(tmp_path)) == {"X"}


class TestPatchUrls:
    def test_commit_url_gets_patch_suffix(self):
        assert patch_urls(["https://github.com/a/b/commit/abc"]) == [
            "https://github.com/a/b/commit/abc.patch"
        ]

    def test_pull_request_url(self):
        assert patch_urls(["https://github.com/a/b/pull/12"]) == [
            "https://github.com/a/b/pull/12.patch"
        ]

    def test_already_a_patch_is_untouched(self):
        assert patch_urls(["https://x/y.patch"]) == ["https://x/y.patch"]

    def test_unrelated_urls_dropped(self):
        assert patch_urls(["https://example.com/advisory"]) == []

    def test_deduplicated(self):
        url = "https://github.com/a/b/commit/abc"
        assert len(patch_urls([url, url + "/"])) == 1


class TestResolveSymbols:
    def test_curated_beats_derivation(self, curated_dir, no_network):
        advisory = Advisory(
            id="GHSA-h5c8-rqwp-cp95", package="jinja2", installed_version="3.1.2",
            aliases=["CVE-2024-22195"],
            fix_commits=["https://github.com/pallets/jinja/commit/abc"],
        )
        symbols, confidence = resolve_symbols(
            advisory, curated=load_curated(curated_dir), fetcher=None,
        )
        assert confidence is Confidence.CURATED
        assert symbols[0].qualname == "jinja2.filters.do_xmlattr"

    def test_falls_back_to_derivation(self, tmp_path, jinja_patch, monkeypatch):
        fetcher = PatchFetcher(cache_dir=tmp_path, offline=True)
        monkeypatch.setattr(fetcher, "fetch", lambda url: jinja_patch)
        advisory = Advisory(
            id="GHSA-UNCURATED", package="jinja2", installed_version="3.1.2",
            fix_commits=["https://github.com/pallets/jinja/commit/abc"],
        )
        symbols, confidence = resolve_symbols(
            advisory, curated={}, fetcher=fetcher, top_levels=["jinja2"],
        )
        assert confidence is Confidence.DERIVED
        assert any(s.qualname == "jinja2.filters.do_xmlattr" for s in symbols)

    def test_no_data_reports_none(self, no_network):
        advisory = Advisory(id="X", package="p", installed_version="1.0")
        symbols, confidence = resolve_symbols(advisory, curated={}, fetcher=None)
        assert symbols == [] and confidence is Confidence.NONE


class TestPatchFetcherOffline:
    def test_offline_never_hits_the_network(self, tmp_path, no_network):
        fetcher = PatchFetcher(cache_dir=tmp_path, offline=True)
        assert fetcher.fetch("https://github.com/a/b/commit/x.patch") is None

    def test_reads_from_cache(self, tmp_path):
        import hashlib

        url = "https://github.com/a/b/commit/x.patch"
        key = hashlib.sha256(url.encode()).hexdigest()[:20]
        tmp_path.mkdir(parents=True, exist_ok=True)
        (tmp_path / f"{key}.patch").write_text("cached content")
        fetcher = PatchFetcher(cache_dir=tmp_path, offline=True)
        assert fetcher.fetch(url) == "cached content"
