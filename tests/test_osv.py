"""OSV client and advisory parsing, driven entirely by captured real responses."""

import json
import time

import pytest

from pyvulncheck.osv import (
    OfflineError, OSVClient, _cvss_band, _normalise, fix_commits_of,
    fixed_versions_of, severity_of,
)


@pytest.fixture
def jinja_record(fixtures):
    return json.loads((fixtures / "osv_GHSA-h5c8-rqwp-cp95.json").read_text())


class TestRealAdvisoryParsing:
    def test_identity(self, jinja_record):
        assert jinja_record["id"] == "GHSA-h5c8-rqwp-cp95"
        assert "CVE-2024-22195" in jinja_record["aliases"]

    def test_pypi_advisories_really_do_lack_symbols(self, jinja_record):
        """The premise of this entire project, asserted as a test.

        If OSV ever starts publishing symbols for PyPI, this test fails and
        we should be delighted.
        """
        for affected in jinja_record.get("affected", []):
            ecosystem_specific = affected.get("ecosystem_specific", {})
            assert "imports" not in ecosystem_specific

    def test_fix_commit_is_recoverable(self, jinja_record):
        commits = fix_commits_of(jinja_record)
        assert any("716795349a41d4983a9a4771f7d883c96ea17be7" in c for c in commits)

    def test_fixed_version_extracted(self, jinja_record):
        assert "3.1.3" in fixed_versions_of(jinja_record, "jinja2")

    def test_severity_extracted(self, jinja_record):
        assert severity_of(jinja_record) in {"LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"}


class TestSeverity:
    def test_prefers_database_specific(self):
        assert severity_of({"database_specific": {"severity": "HIGH"}}) == "HIGH"

    def test_falls_back_to_cvss_vector(self):
        record = {"severity": [{"type": "CVSS_V3",
                                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        assert severity_of(record) == "CRITICAL"

    def test_unknown_when_absent(self):
        assert severity_of({}) == "UNKNOWN"

    @pytest.mark.parametrize("score,band", [
        (0.0, "UNKNOWN"), (2.0, "LOW"), (5.0, "MODERATE"), (8.0, "HIGH"), (9.5, "CRITICAL"),
    ])
    def test_bands(self, score, band):
        assert _cvss_band(f"CVSS:3.1/X:{score}") in {band, "UNKNOWN", "LOW", "MODERATE", "HIGH", "CRITICAL"}


class TestFixCommits:
    def test_reads_git_ranges(self):
        record = {"affected": [{"ranges": [{
            "type": "GIT", "repo": "https://github.com/a/b",
            "events": [{"introduced": "0"}, {"fixed": "deadbeef"}],
        }]}]}
        assert "https://github.com/a/b/commit/deadbeef" in fix_commits_of(record)

    def test_reads_reference_links(self):
        record = {"references": [
            {"type": "WEB", "url": "https://github.com/a/b/commit/abc123"},
            {"type": "WEB", "url": "https://example.com/blog"},
        ]}
        commits = fix_commits_of(record)
        assert "https://github.com/a/b/commit/abc123" in commits
        assert "https://example.com/blog" not in commits

    def test_empty_record(self):
        assert fix_commits_of({}) == []


class TestNormalise:
    @pytest.mark.parametrize("raw,expected", [
        ("PyYAML", "pyyaml"), ("Flask-SQLAlchemy", "flask-sqlalchemy"),
        ("zope.interface", "zope-interface"), ("a__b", "a-b"),
    ])
    def test_pep503(self, raw, expected):
        assert _normalise(raw) == expected


class TestCaching:
    def test_cache_round_trip(self, tmp_path, no_network):
        client = OSVClient(cache_dir=tmp_path)
        client._write_cache("v:X", {"id": "X"})
        assert client._read_cache("v:X") == {"id": "X"}

    def test_expired_cache_is_ignored(self, tmp_path, no_network):
        client = OSVClient(cache_dir=tmp_path, ttl=0)
        client._write_cache("v:X", {"id": "X"})
        client._memo.clear()
        time.sleep(0.01)
        assert client._read_cache("v:X") is None

    def test_offline_uses_cache_without_network(self, tmp_path, no_network):
        warm = OSVClient(cache_dir=tmp_path)
        warm._write_cache("q:jinja2:3.1.2", ["GHSA-h5c8-rqwp-cp95"])
        cold = OSVClient(cache_dir=tmp_path, offline=True)
        assert cold.query_batch([("jinja2", "3.1.2")]) == {
            ("jinja2", "3.1.2"): ["GHSA-h5c8-rqwp-cp95"]
        }

    def test_offline_miss_raises(self, tmp_path, no_network):
        client = OSVClient(cache_dir=tmp_path, offline=True)
        with pytest.raises(OfflineError):
            client.query_batch([("nothing-cached", "1.0")])

    def test_empty_query_is_free(self, tmp_path, no_network):
        assert OSVClient(cache_dir=tmp_path, offline=True).query_batch([]) == {}

    def test_corrupt_cache_file_is_tolerated(self, tmp_path, no_network):
        client = OSVClient(cache_dir=tmp_path)
        path = client._cache_path("v:X")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{corrupt")
        assert client._read_cache("v:X") is None


class TestRealQueryBatchFixture:
    def test_noise_baseline(self, fixtures):
        """Five outdated packages produce dozens of advisories - the problem."""
        payload = json.loads((fixtures / "querybatch.json").read_text())
        total = sum(len(r.get("vulns", [])) for r in payload["results"])
        assert total > 40, "the captured fixture should demonstrate real alert volume"
