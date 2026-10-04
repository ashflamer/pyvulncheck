"""Call-graph construction, including the cases it deliberately cannot resolve."""

import pytest

from pyvulncheck.callgraph import (
    CallGraph, analyse_source, build_call_graph, iter_python_files, module_name_for,
)


def graph_from(source: str, module: str = "app.mod") -> CallGraph:
    from pathlib import Path

    graph = CallGraph()
    analyse_source(graph, source, module, Path(f"/fake/{module}.py"))
    return graph


class TestDefinitions:
    def test_function(self):
        g = graph_from("def handler():\n    pass\n")
        assert "app.mod.handler" in g.definitions

    def test_async_function(self):
        g = graph_from("async def handler():\n    pass\n")
        assert "app.mod.handler" in g.definitions

    def test_method_is_qualified_by_class(self):
        g = graph_from("class View:\n    def get(self):\n        pass\n")
        assert "app.mod.View.get" in g.definitions
        assert "app.mod.View" in g.definitions

    def test_nested_function(self):
        g = graph_from("def outer():\n    def inner():\n        pass\n")
        assert "app.mod.outer.inner" in g.definitions

    def test_module_scope_pseudo_node(self):
        g = graph_from("x = 1\n")
        assert "app.mod:<module>" in g.definitions

    def test_line_numbers_recorded(self):
        g = graph_from("\n\ndef handler():\n    pass\n")
        assert g.definitions["app.mod.handler"].line == 3

    def test_syntax_error_does_not_raise(self):
        g = graph_from("def broken(:\n")
        assert g.definitions == {} or "app.mod:<module>" not in g.definitions


class TestEdges:
    def test_import_from_call(self):
        g = graph_from("from jinja2.filters import do_xmlattr\n"
                       "def render():\n    return do_xmlattr(1, 2)\n")
        assert "jinja2.filters.do_xmlattr" in g.edges["app.mod.render"]

    def test_dotted_import_call(self):
        g = graph_from("import yaml\ndef load(t):\n    return yaml.safe_load(t)\n")
        assert "yaml.safe_load" in g.edges["app.mod.load"]

    def test_aliased_import(self):
        g = graph_from("import numpy as np\ndef go():\n    return np.array([1])\n")
        assert "numpy.array" in g.edges["app.mod.go"]

    def test_aliased_from_import(self):
        g = graph_from("from yaml import load as unsafe_load\n"
                       "def go(t):\n    return unsafe_load(t)\n")
        assert "yaml.load" in g.edges["app.mod.go"]

    def test_relative_import(self):
        g = graph_from("from .helpers import render\ndef view():\n    return render()\n",
                       module="app.views")
        assert "app.helpers.render" in g.edges["app.views.view"]

    def test_local_function_call(self):
        g = graph_from("def helper():\n    pass\ndef caller():\n    return helper()\n")
        assert "app.mod.helper" in g.edges["app.mod.caller"]

    def test_self_method_call(self):
        g = graph_from("class V:\n"
                       "    def get(self):\n        return self.render()\n"
                       "    def render(self):\n        pass\n")
        assert "app.mod.V.render" in g.edges["app.mod.V.get"]

    def test_cls_method_call(self):
        g = graph_from("class V:\n"
                       "    @classmethod\n"
                       "    def make(cls):\n        return cls.build()\n"
                       "    @classmethod\n"
                       "    def build(cls):\n        pass\n")
        assert "app.mod.V.build" in g.edges["app.mod.V.make"]

    def test_base_class_edge(self):
        g = graph_from("from werkzeug import Base\nclass Mine(Base):\n    pass\n")
        assert "werkzeug.Base" in g.edges["app.mod.Mine"]

    def test_module_level_call_attributed_to_module(self):
        g = graph_from("import yaml\nyaml.load('x')\n")
        assert "yaml.load" in g.edges["app.mod:<module>"]

    def test_deep_attribute_chain(self):
        g = graph_from("import a\ndef f():\n    return a.b.c.d()\n")
        assert "a.b.c.d" in g.edges["app.mod.f"]


class TestDynamicCalls:
    def test_unresolved_receiver_recorded_by_name(self):
        g = graph_from("def handle(obj):\n    return obj.parse(1)\n")
        assert "parse" in g.dynamic["app.mod.handle"]

    def test_resolved_calls_are_not_dynamic(self):
        g = graph_from("import yaml\ndef f(t):\n    return yaml.safe_load(t)\n")
        assert "app.mod.f" not in g.dynamic

    def test_call_on_subscript_is_dynamic(self):
        g = graph_from("R = {}\ndef f(k):\n    return R[k].parse()\n")
        assert "parse" in g.dynamic["app.mod.f"]

    def test_call_on_call_result_is_dynamic(self):
        g = graph_from("def factory():\n    pass\n"
                       "def f():\n    return factory().parse()\n")
        assert "parse" in g.dynamic["app.mod.f"]


class TestImports:
    def test_records_top_level_and_full(self):
        g = graph_from("import jinja2.filters\n")
        assert "jinja2" in g.imported_modules
        assert "jinja2.filters" in g.imported_modules

    def test_from_import_records_module(self):
        g = graph_from("from requests.sessions import Session\n")
        assert "requests" in g.imported_modules

    def test_star_import_does_not_crash(self):
        g = graph_from("from os import *\n")
        assert "os" in g.imported_modules


class TestModuleNaming:
    def test_strips_src_prefix(self, tmp_path):
        file = tmp_path / "src" / "pkg" / "mod.py"
        file.parent.mkdir(parents=True)
        file.write_text("")
        assert module_name_for(file, tmp_path) == "pkg.mod"

    def test_package_init(self, tmp_path):
        file = tmp_path / "pkg" / "__init__.py"
        file.parent.mkdir(parents=True)
        file.write_text("")
        assert module_name_for(file, tmp_path) == "pkg"


class TestFileDiscovery:
    def test_skips_virtualenvs_and_caches(self, tmp_path):
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "main.py").write_text("")
        for noise in (".venv", "__pycache__", "node_modules", "build"):
            (tmp_path / noise).mkdir()
            (tmp_path / noise / "junk.py").write_text("")
        found = {p.name for p in iter_python_files(tmp_path)}
        assert found == {"main.py"}

    def test_single_file_target(self, tmp_path):
        file = tmp_path / "one.py"
        file.write_text("")
        assert iter_python_files(file) == [file]


class TestBuildCallGraph:
    def test_marks_dependency_code_as_third_party(self, tmp_path):
        (tmp_path / "app.py").write_text("def f():\n    pass\n")
        dep = tmp_path / "dep.py"
        dep.write_text("def g():\n    pass\n")
        g = build_call_graph([tmp_path / "app.py"], dependency_modules={"dep": dep})
        assert g.definitions["app.f"].is_first_party
        assert not g.definitions["dep.g"].is_first_party

    def test_stats_are_reported(self, tmp_path):
        (tmp_path / "a.py").write_text("import os\ndef f():\n    os.getcwd()\n")
        stats = build_call_graph([tmp_path]).stats()
        assert stats["definitions"] >= 1 and stats["edges"] >= 1
