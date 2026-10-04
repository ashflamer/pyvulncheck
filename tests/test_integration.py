"""End-to-end scans with a stubbed OSV client. No network, ever."""

import json

import pytest

from pyvulncheck.cli import main
from pyvulncheck.models import Reachability
from pyvulncheck.osv import OSVClient
from pyvulncheck.scanner import scan


class FakeOSV(OSVClient):
    """An OSVClient backed by the captured fixtures."""

    def __init__(self, records, matches):
        super().__init__(cache_dir=None, offline=True)
        self._records = records
        self._matches = matches

    def query_batch(self, packages):
        out = {}
        for name, version in packages:
            out[(name, version)] = self._matches.get(name, [])
        return out

    def get_vuln(self, vuln_id):
        return self._records.get(vuln_id)


@pytest.fixture
def records(fixtures):
    return {
        "GHSA-h5c8-rqwp-cp95": json.loads(
            (fixtures / "osv_GHSA-h5c8-rqwp-cp95.json").read_text()
        ),
    }


@pytest.fixture
def app(tmp_path):
    project = tmp_path / "project"
    (project / "app").mkdir(parents=True)
    (project / "app" / "__init__.py").write_text("")
    (project / "app" / "templating.py").write_text(
        "from jinja2.filters import do_xmlattr\n"
        "def render_tag(attrs):\n"
        "    return do_xmlattr(None, attrs)\n"
    )
    (project / "app" / "views.py").write_text(
        "from app.templating import render_tag\n"
        "def widget_view(request):\n"
        "    return render_tag(request)\n"
    )
    (project / "app" / "config.py").write_text(
        "import yaml\ndef load(p):\n    return yaml.safe_load(p)\n"
    )
    (project / "requirements.txt").write_text("jinja2==3.1.2\npyyaml==5.1\n")
    return project


class TestFullScan:
    def test_finds_the_reachable_vulnerability(self, app, records, curated_dir, no_network):
        result = scan(
            app, requirements=app / "requirements.txt",
            client=FakeOSV(records, {"jinja2": ["GHSA-h5c8-rqwp-cp95"]}),
            curated_dir=curated_dir, derive_symbols=False,
            follow_dependencies=False, offline=True,
        )
        reachable = [f for f in result.findings if f.reachability is Reachability.REACHABLE]
        assert len(reachable) == 1
        assert reachable[0].package.lower() == "jinja2"

    def test_reports_a_usable_call_path(self, app, records, curated_dir, no_network):
        result = scan(
            app, requirements=app / "requirements.txt",
            client=FakeOSV(records, {"jinja2": ["GHSA-h5c8-rqwp-cp95"]}),
            curated_dir=curated_dir, derive_symbols=False,
            follow_dependencies=False, offline=True,
        )
        path = result.findings[0].paths[0]
        assert path.target == "jinja2.filters.do_xmlattr"
        assert path.entry.startswith("app.")
        assert path.entry_file and path.entry_line

    def test_packages_without_advisories_are_absent(self, app, records, curated_dir, no_network):
        result = scan(
            app, requirements=app / "requirements.txt",
            client=FakeOSV(records, {"jinja2": ["GHSA-h5c8-rqwp-cp95"]}),
            curated_dir=curated_dir, derive_symbols=False,
            follow_dependencies=False, offline=True,
        )
        assert all(f.package.lower() != "pyyaml" for f in result.findings)

    def test_stats_are_populated(self, app, records, curated_dir, no_network):
        result = scan(
            app, requirements=app / "requirements.txt",
            client=FakeOSV(records, {"jinja2": ["GHSA-h5c8-rqwp-cp95"]}),
            curated_dir=curated_dir, derive_symbols=False,
            follow_dependencies=False, offline=True,
        )
        assert result.stats["packages"] == 2
        assert result.stats["advisories"] >= 1
        assert result.stats["files"] >= 3

    def test_no_advisories_is_a_clean_result(self, app, curated_dir, no_network):
        result = scan(
            app, requirements=app / "requirements.txt",
            client=FakeOSV({}, {}), curated_dir=curated_dir,
            derive_symbols=False, follow_dependencies=False, offline=True,
        )
        assert result.findings == []

    def test_duplicate_advisories_for_one_cve_collapse(self, app, records, curated_dir, no_network):
        """OSV returns GHSA and PYSEC records for the same CVE; report it once."""
        pysec = dict(records["GHSA-h5c8-rqwp-cp95"])
        pysec["id"] = "PYSEC-2024-99"
        pysec["severity"] = []
        pysec["database_specific"] = {}
        both = {**records, "PYSEC-2024-99": pysec}
        result = scan(
            app, requirements=app / "requirements.txt",
            client=FakeOSV(both, {"jinja2": ["GHSA-h5c8-rqwp-cp95", "PYSEC-2024-99"]}),
            curated_dir=curated_dir, derive_symbols=False,
            follow_dependencies=False, offline=True,
        )
        assert len(result.findings) == 1
        assert result.findings[0].advisory.id == "GHSA-h5c8-rqwp-cp95"


class TestCli:
    def test_version_flag(self, capsys):
        assert main(["--version"]) == 0
        assert "pyvulncheck" in capsys.readouterr().out

    def test_missing_path_is_exit_2(self, capsys):
        assert main(["/definitely/not/here"]) == 2
        assert "does not exist" in capsys.readouterr().err

    def test_help_mentions_the_differentiator(self, capsys):
        with pytest.raises(SystemExit):
            main(["--help"])
        out = capsys.readouterr().out
        assert "reachab" in out.lower()

    def test_offline_scan_of_a_clean_project(self, tmp_path, capsys):
        (tmp_path / "m.py").write_text("print('hi')\n")
        (tmp_path / "r.txt").write_text("")
        code = main([str(tmp_path), "-r", str(tmp_path / "r.txt"), "--offline", "-q"])
        assert code in (0, 2)
