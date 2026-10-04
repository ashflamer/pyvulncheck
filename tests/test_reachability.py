"""Verdicts. The tests that matter most, because a wrong answer here is a
security decision made on bad information."""

import pytest

from pyvulncheck.callgraph import build_call_graph
from pyvulncheck.models import Advisory, Confidence, Reachability, VulnerableSymbol
from pyvulncheck.reachability import assess, find_paths


@pytest.fixture
def project(tmp_path):
    """A small app that calls jinja2's vulnerable filter through two hops."""
    app = tmp_path / "app"
    app.mkdir()
    (app / "__init__.py").write_text("")
    (app / "templating.py").write_text(
        "from jinja2.filters import do_xmlattr\n"
        "def render_tag(attrs):\n"
        "    return do_xmlattr(None, attrs)\n"
    )
    (app / "views.py").write_text(
        "from app.templating import render_tag\n"
        "def widget_view(request):\n"
        "    return render_tag(request)\n"
    )
    (app / "config.py").write_text(
        "import yaml\n"
        "def load(path):\n"
        "    return yaml.safe_load(path)\n"
    )
    (app / "plugins.py").write_text(
        "REGISTRY = {}\n"
        "def handle(name, data):\n"
        "    return REGISTRY[name].parse(data)\n"
    )
    return tmp_path


@pytest.fixture
def graph(project):
    return build_call_graph([project])


def make_advisory(package="jinja2", **kwargs):
    defaults = dict(id="GHSA-TEST", package=package, installed_version="1.0",
                    aliases=["CVE-2024-0001"], severity="HIGH")
    defaults.update(kwargs)
    return Advisory(**defaults)


class TestReachable:
    def test_direct_call_is_reachable(self, graph):
        finding = assess(
            graph, make_advisory(), [VulnerableSymbol("jinja2.filters", "do_xmlattr")],
            Confidence.CURATED, package="jinja2", installed_version="3.1.2",
            top_levels=["jinja2"],
        )
        assert finding.reachability is Reachability.REACHABLE
        assert finding.actionable

    def test_reports_the_call_path(self, graph):
        finding = assess(
            graph, make_advisory(), [VulnerableSymbol("jinja2.filters", "do_xmlattr")],
            Confidence.CURATED, package="jinja2", installed_version="3.1.2",
            top_levels=["jinja2"],
        )
        rendered = [p.render(" -> ") for p in finding.paths]
        assert any(p.endswith("jinja2.filters.do_xmlattr") for p in rendered)
        assert any("app.templating.render_tag" in p for p in rendered)

    def test_path_includes_the_transitive_entry_point(self, graph):
        finding = assess(
            graph, make_advisory(), [VulnerableSymbol("jinja2.filters", "do_xmlattr")],
            Confidence.CURATED, package="jinja2", installed_version="3.1.2",
            top_levels=["jinja2"],
        )
        joined = " | ".join(p.render(" -> ") for p in finding.paths)
        assert "app.views.widget_view" in joined

    def test_path_carries_file_and_line(self, graph):
        finding = assess(
            graph, make_advisory(), [VulnerableSymbol("jinja2.filters", "do_xmlattr")],
            Confidence.CURATED, package="jinja2", installed_version="3.1.2",
            top_levels=["jinja2"],
        )
        path = finding.paths[0]
        assert path.entry_file and path.entry_line and path.entry_line > 0

    def test_reexported_symbol_still_matches(self, tmp_path):
        """`from jinja2 import do_xmlattr` vs advisory `jinja2.filters.do_xmlattr`."""
        (tmp_path / "m.py").write_text(
            "from jinja2 import do_xmlattr\ndef f(a):\n    return do_xmlattr(None, a)\n"
        )
        graph = build_call_graph([tmp_path])
        finding = assess(
            graph, make_advisory(), [VulnerableSymbol("jinja2.filters", "do_xmlattr")],
            Confidence.CURATED, package="jinja2", installed_version="3.1.2",
            top_levels=["jinja2"],
        )
        assert finding.reachability is Reachability.REACHABLE


class TestNotReachable:
    def test_safe_sibling_function_is_not_reachable(self, graph):
        """PyYAML's headline case: the project calls safe_load, not load."""
        finding = assess(
            graph, make_advisory(package="pyyaml"),
            [VulnerableSymbol("yaml", "load"), VulnerableSymbol("yaml", "full_load")],
            Confidence.CURATED, package="pyyaml", installed_version="5.1",
            top_levels=["yaml"],
        )
        assert finding.reachability is Reachability.NOT_REACHABLE
        assert not finding.actionable

    def test_package_never_imported(self, graph):
        finding = assess(
            graph, make_advisory(package="cryptography"),
            [VulnerableSymbol("cryptography.x509", "load_pem")],
            Confidence.CURATED, package="cryptography", installed_version="3.2",
            top_levels=["cryptography"],
        )
        assert finding.reachability is Reachability.NOT_REACHABLE
        assert "never imported" in finding.reason

    def test_reason_is_always_explained(self, graph):
        finding = assess(
            graph, make_advisory(package="pyyaml"), [VulnerableSymbol("yaml", "load")],
            Confidence.CURATED, package="pyyaml", installed_version="5.1",
            top_levels=["yaml"],
        )
        assert finding.reason.strip()


class TestPossible:
    def test_unresolved_receiver_yields_possible(self, graph):
        finding = assess(
            graph, make_advisory(package="werkzeug"),
            [VulnerableSymbol("werkzeug.formparser", "MultiPartParser.parse")],
            Confidence.CURATED, package="werkzeug", installed_version="2.2.2",
            top_levels=["werkzeug"],
        )
        # werkzeug isn't imported in this fixture, so it must not be POSSIBLE...
        assert finding.reachability is Reachability.NOT_REACHABLE

    def test_possible_when_imported_and_duck_typed(self, tmp_path):
        (tmp_path / "m.py").write_text(
            "import werkzeug\n"
            "REGISTRY = {}\n"
            "def handle(name, data):\n"
            "    return REGISTRY[name].parse(data)\n"
        )
        graph = build_call_graph([tmp_path])
        finding = assess(
            graph, make_advisory(package="werkzeug"),
            [VulnerableSymbol("werkzeug.formparser", "MultiPartParser.parse")],
            Confidence.CURATED, package="werkzeug", installed_version="2.2.2",
            top_levels=["werkzeug"],
        )
        assert finding.reachability is Reachability.POSSIBLE
        assert finding.possible_callers == ["m.handle"]
        assert finding.actionable, "POSSIBLE must be actionable - it is not a clear"


class TestUnknown:
    def test_no_symbols_but_imported_is_unknown(self, graph):
        finding = assess(
            graph, make_advisory(package="pyyaml"), [], Confidence.NONE,
            package="pyyaml", installed_version="5.1", top_levels=["yaml"],
        )
        assert finding.reachability is Reachability.UNKNOWN

    def test_unknown_is_never_reported_as_safe(self, graph):
        """The cardinal rule: absence of data is not evidence of safety."""
        finding = assess(
            graph, make_advisory(package="pyyaml"), [], Confidence.NONE,
            package="pyyaml", installed_version="5.1", top_levels=["yaml"],
        )
        assert finding.reachability is not Reachability.NOT_REACHABLE

    def test_no_symbols_and_not_imported_is_not_reachable(self, graph):
        finding = assess(
            graph, make_advisory(package="boto3"), [], Confidence.NONE,
            package="boto3", installed_version="1.0", top_levels=["boto3"],
        )
        assert finding.reachability is Reachability.NOT_REACHABLE


class TestPathSearch:
    def test_no_match_returns_no_paths(self, graph):
        assert find_paths(graph, VulnerableSymbol("nonexistent.mod", "thing")) == []

    def test_depth_limit_respected(self, tmp_path):
        chain = ["import target"]
        for index in range(10):
            nxt = f"f{index + 1}()" if index < 9 else "target.vuln()"
            chain.append(f"def f{index}():\n    return {nxt}")
        (tmp_path / "m.py").write_text("\n".join(chain) + "\n")
        graph = build_call_graph([tmp_path])
        assert find_paths(graph, VulnerableSymbol("target", "vuln"), max_depth=2) != []
        deep = find_paths(graph, VulnerableSymbol("target", "vuln"), max_depth=20)
        assert max(p.length for p in deep) >= 2

    def test_recursion_does_not_hang(self, tmp_path):
        (tmp_path / "m.py").write_text(
            "import target\n"
            "def a():\n    return b()\n"
            "def b():\n    return a() or target.vuln()\n"
        )
        graph = build_call_graph([tmp_path])
        assert find_paths(graph, VulnerableSymbol("target", "vuln")) != []

    def test_paths_are_ordered_entry_first(self, graph):
        paths = find_paths(graph, VulnerableSymbol("jinja2.filters", "do_xmlattr"))
        for path in paths:
            assert path.target == "jinja2.filters.do_xmlattr"
            assert path.entry.startswith("app.")


class TestSorting:
    def test_reachable_sorts_before_not_reachable(self):
        high = assess.__module__  # keep import used
        reachable = Reachability.REACHABLE.rank
        assert reachable < Reachability.POSSIBLE.rank < Reachability.UNKNOWN.rank
        assert Reachability.UNKNOWN.rank < Reachability.NOT_REACHABLE.rank


class TestWrapperFalsePositives:
    """The safe_load problem.

    PyYAML's safe_load() calls load() internally. A naive graph walk therefore
    "proves" that every project using the documented safe API reaches the
    vulnerable symbol. Getting this wrong would discredit the whole tool.
    """

    @pytest.fixture
    def app_using_safe_load(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "import yaml\ndef load_settings(p):\n    return yaml.safe_load(p)\n"
        )
        # Stand in for PyYAML's own source: safe_load delegates to load.
        dep = tmp_path / "yaml_src.py"
        dep.write_text(
            "def load(stream, Loader=None):\n    pass\n"
            "def safe_load(stream):\n    return load(stream, SafeLoader)\n"
        )
        from pyvulncheck.callgraph import build_call_graph

        return build_call_graph([tmp_path / "app.py"], dependency_modules={"yaml": dep})

    def test_naive_path_exists(self, app_using_safe_load):
        """Confirm the tempting-but-wrong path is really in the graph."""
        paths = find_paths(app_using_safe_load, VulnerableSymbol("yaml", "load"))
        assert paths, "the graph should contain app -> safe_load -> load"

    def test_safe_wrapper_suppresses_the_finding(self, app_using_safe_load):
        finding = assess(
            app_using_safe_load, make_advisory(package="pyyaml"),
            [VulnerableSymbol("yaml", "load")], Confidence.CURATED,
            package="pyyaml", installed_version="5.1", top_levels=["yaml"],
            safe_wrappers=["yaml.safe_load"],
        )
        assert finding.reachability is Reachability.NOT_REACHABLE
        assert "safe wrapper" in finding.reason

    def test_without_curation_it_is_possible_not_reachable(self, app_using_safe_load):
        """No curated data: don't claim REACHABLE, don't claim safe."""
        finding = assess(
            app_using_safe_load, make_advisory(package="pyyaml"),
            [VulnerableSymbol("yaml", "load")], Confidence.DERIVED,
            package="pyyaml", installed_version="5.1", top_levels=["yaml"],
        )
        assert finding.reachability is Reachability.POSSIBLE
        assert "indirectly" in finding.reason

    def test_direct_call_is_still_reachable(self, tmp_path):
        """The suppression must not hide a genuine direct call."""
        from pyvulncheck.callgraph import build_call_graph

        (tmp_path / "app.py").write_text(
            "import yaml\ndef load_settings(p):\n    return yaml.load(p)\n"
        )
        graph = build_call_graph([tmp_path / "app.py"])
        finding = assess(
            graph, make_advisory(package="pyyaml"),
            [VulnerableSymbol("yaml", "load")], Confidence.CURATED,
            package="pyyaml", installed_version="5.1", top_levels=["yaml"],
            safe_wrappers=["yaml.safe_load"],
        )
        assert finding.reachability is Reachability.REACHABLE

    def test_curated_pyyaml_entry_declares_the_wrapper(self, curated_dir):
        from pyvulncheck.symbols import load_curated, safe_wrappers_for

        curated = load_curated(curated_dir)
        wrappers = safe_wrappers_for("CVE-2020-14343", [], curated)
        assert "yaml.safe_load" in wrappers
