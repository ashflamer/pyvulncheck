"""Output formats. The text report is the product, so it is tested like one."""

import json

import pytest

from pyvulncheck.models import (
    Advisory, CallPath, Confidence, Finding, Reachability, VulnerableSymbol,
)
from pyvulncheck.report import exit_code, render_json, render_sarif, render_text


def make_finding(reachability=Reachability.REACHABLE, **kwargs):
    advisory = Advisory(
        id=kwargs.pop("id", "GHSA-h5c8-rqwp-cp95"),
        package="jinja2", installed_version="3.1.2",
        aliases=["CVE-2024-22195"], severity=kwargs.pop("severity", "MODERATE"),
        summary="HTML attribute injection via the xmlattr filter",
        fixed_versions=["3.1.3"],
    )
    path = CallPath(
        nodes=["app.views.widget_view", "app.templating.render_tag",
               "jinja2.filters.do_xmlattr"],
        entry_file="app/views.py", entry_line=7,
    )
    return Finding(
        advisory=advisory,
        package=kwargs.pop("package", "jinja2"),
        installed_version="3.1.2",
        reachability=reachability,
        symbols=[VulnerableSymbol("jinja2.filters", "do_xmlattr")],
        matched_symbols=[VulnerableSymbol("jinja2.filters", "do_xmlattr")],
        paths=[path] if reachability is Reachability.REACHABLE else [],
        confidence=Confidence.CURATED,
        imported=True,
        reason=kwargs.pop("reason", "call path reaches jinja2.filters.do_xmlattr"),
        **kwargs,
    )


class TestTextReport:
    def test_shows_the_call_path(self):
        out = render_text([make_finding()])
        assert "app.views.widget_view" in out
        assert "jinja2.filters.do_xmlattr" in out

    def test_shows_file_and_line(self):
        assert ":7" in render_text([make_finding()])

    def test_shows_the_fix_version(self):
        assert "3.1.3" in render_text([make_finding()])

    def test_prefers_the_cve_id(self):
        assert "CVE-2024-22195" in render_text([make_finding()])

    def test_states_symbol_provenance(self):
        assert "curated" in render_text([make_finding()]).lower()

    def test_hides_unreachable_by_default(self):
        out = render_text([make_finding(Reachability.NOT_REACHABLE)])
        assert "hidden" in out

    def test_all_flag_reveals_them(self):
        out = render_text([make_finding(Reachability.NOT_REACHABLE)], show_all=True)
        assert "No call path found" in out

    def test_always_caveats_not_reachable(self):
        """Refusing to let 'no path' read as 'safe' is a correctness requirement."""
        out = render_text([make_finding(Reachability.NOT_REACHABLE)])
        assert "not a proof of safety" in out.lower()

    def test_counts_actionable_findings(self):
        out = render_text([
            make_finding(Reachability.REACHABLE),
            make_finding(Reachability.NOT_REACHABLE, id="GHSA-OTHER"),
            make_finding(Reachability.NOT_REACHABLE, id="GHSA-THIRD"),
        ])
        assert "3 advisories affect installed packages" in out
        assert "1 need attention" in out

    def test_empty_result_is_reassuring(self):
        assert "No known vulnerabilities" in render_text([])

    def test_colour_disabled_emits_no_escapes(self):
        assert "\033[" not in render_text([make_finding()], colour=False)

    def test_colour_enabled_emits_escapes(self):
        assert "\033[" in render_text([make_finding()], colour=True)

    def test_possible_explains_the_uncertainty(self):
        finding = make_finding(Reachability.POSSIBLE)
        finding.possible_callers = ["app.plugins.handle"]
        out = render_text([finding])
        assert "receiver could not be resolved" in out
        assert "app.plugins.handle" in out

    def test_unknown_has_its_own_section(self):
        out = render_text([make_finding(Reachability.UNKNOWN)])
        assert "No symbol data" in out

    def test_reachable_listed_before_possible(self):
        out = render_text([
            make_finding(Reachability.POSSIBLE, id="GHSA-P"),
            make_finding(Reachability.REACHABLE, id="GHSA-R"),
        ])
        assert out.index("your code can reach") < out.index("Possibly reachable")


class TestJsonReport:
    def test_is_valid_json(self):
        json.loads(render_json([make_finding()]))

    def test_summary_counts(self):
        payload = json.loads(render_json([
            make_finding(Reachability.REACHABLE),
            make_finding(Reachability.NOT_REACHABLE, id="X"),
        ]))
        assert payload["summary"]["total"] == 2
        assert payload["summary"]["actionable"] == 1

    def test_finding_carries_everything_needed(self):
        finding = json.loads(render_json([make_finding()]))["findings"][0]
        for key in ("id", "cve", "package", "installed_version", "fixed_version",
                    "severity", "reachability", "symbol_confidence",
                    "vulnerable_symbols", "paths", "reason"):
            assert key in finding

    def test_path_nodes_preserved(self):
        finding = json.loads(render_json([make_finding()]))["findings"][0]
        assert finding["paths"][0]["nodes"][-1] == "jinja2.filters.do_xmlattr"

    def test_empty_is_still_valid(self):
        assert json.loads(render_json([]))["summary"]["total"] == 0


class TestSarifReport:
    def test_schema_shape(self):
        payload = json.loads(render_sarif([make_finding()]))
        assert payload["version"] == "2.1.0"
        assert payload["runs"][0]["tool"]["driver"]["name"] == "pyvulncheck"

    def test_only_actionable_findings_become_results(self):
        payload = json.loads(render_sarif([
            make_finding(Reachability.REACHABLE),
            make_finding(Reachability.NOT_REACHABLE, id="GHSA-QUIET"),
        ]))
        assert len(payload["runs"][0]["results"]) == 1

    def test_reachable_is_error_level(self):
        payload = json.loads(render_sarif([make_finding()]))
        assert payload["runs"][0]["results"][0]["level"] == "error"

    def test_possible_is_warning_level(self):
        payload = json.loads(render_sarif([make_finding(Reachability.POSSIBLE)]))
        assert payload["runs"][0]["results"][0]["level"] == "warning"

    def test_result_has_a_location(self):
        result = json.loads(render_sarif([make_finding()]))["runs"][0]["results"][0]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 7

    def test_security_severity_is_numeric(self):
        rule = json.loads(render_sarif([make_finding()]))["runs"][0]["tool"]["driver"]["rules"][0]
        float(rule["properties"]["security-severity"])

    def test_rules_are_deduplicated(self):
        payload = json.loads(render_sarif([make_finding(), make_finding()]))
        assert len(payload["runs"][0]["tool"]["driver"]["rules"]) == 1


class TestExitCodes:
    def test_reachable_fails_by_default(self):
        assert exit_code([make_finding(Reachability.REACHABLE)]) == 1

    def test_possible_passes_by_default(self):
        assert exit_code([make_finding(Reachability.POSSIBLE)]) == 0

    def test_possible_threshold(self):
        assert exit_code([make_finding(Reachability.POSSIBLE)], fail_on="possible") == 1

    def test_unknown_threshold(self):
        assert exit_code([make_finding(Reachability.UNKNOWN)], fail_on="unknown") == 1

    def test_any_threshold(self):
        assert exit_code([make_finding(Reachability.NOT_REACHABLE)], fail_on="any") == 1

    def test_never_always_passes(self):
        assert exit_code([make_finding(Reachability.REACHABLE)], fail_on="never") == 0

    def test_clean_run_is_zero(self):
        assert exit_code([]) == 0
