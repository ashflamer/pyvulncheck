"""Installed-package discovery and the dist-name -> import-name problem."""

import pytest

from pyvulncheck.discovery import (
    Package, import_name_index, installed_packages, normalise, parse_requirements,
)


class TestNormalise:
    @pytest.mark.parametrize("raw,expected", [
        ("PyYAML", "pyyaml"), ("Flask_Login", "flask-login"),
        ("zope.interface", "zope-interface"), ("Jinja2", "jinja2"),
    ])
    def test_pep503(self, raw, expected):
        assert normalise(raw) == expected


class TestRequirements:
    def test_reads_exact_pins(self, tmp_path):
        file = tmp_path / "requirements.txt"
        file.write_text("jinja2==3.1.2\nrequests==2.25.0\n")
        assert parse_requirements(file) == {"jinja2": "3.1.2", "requests": "2.25.0"}

    def test_skips_comments_and_blanks(self, tmp_path):
        file = tmp_path / "r.txt"
        file.write_text("# a comment\n\njinja2==3.1.2  # inline\n")
        assert parse_requirements(file) == {"jinja2": "3.1.2"}

    def test_skips_ranges(self, tmp_path):
        file = tmp_path / "r.txt"
        file.write_text("jinja2>=3.0\nrequests==2.25.0\n")
        assert parse_requirements(file) == {"requests": "2.25.0"}

    def test_strips_extras(self, tmp_path):
        file = tmp_path / "r.txt"
        file.write_text("celery[redis]==5.3.0\n")
        assert parse_requirements(file) == {"celery": "5.3.0"}

    def test_strips_environment_markers(self, tmp_path):
        file = tmp_path / "r.txt"
        file.write_text('tomli==2.0.1 ; python_version < "3.11"\n')
        assert parse_requirements(file) == {"tomli": "2.0.1"}

    def test_skips_flags(self, tmp_path):
        file = tmp_path / "r.txt"
        file.write_text("-r base.txt\n--index-url https://x\njinja2==3.1.2\n")
        assert parse_requirements(file) == {"jinja2": "3.1.2"}

    def test_normalises_names(self, tmp_path):
        file = tmp_path / "r.txt"
        file.write_text("PyYAML==6.0\n")
        assert parse_requirements(file) == {"pyyaml": "6.0"}

    def test_missing_file_is_empty(self, tmp_path):
        assert parse_requirements(tmp_path / "nope.txt") == {}


class TestInstalledPackages:
    def test_finds_the_running_environment(self):
        packages = installed_packages()
        assert packages, "pytest at minimum should be installed"
        assert "pytest" in packages

    def test_entries_are_well_formed(self):
        for package in installed_packages().values():
            assert package.name == normalise(package.name)
            assert package.version
            assert isinstance(package.top_levels, list)

    def test_no_cache_dirs_leak_into_import_names(self):
        for package in installed_packages().values():
            assert "__pycache__" not in package.top_levels

    def test_import_names_are_identifiers(self):
        for package in installed_packages().values():
            for top in package.top_levels:
                assert top.isidentifier(), f"{package.name} -> {top}"


class TestImportNameIndex:
    def test_maps_import_name_back_to_distribution(self):
        packages = {"pyyaml": Package("pyyaml", "PyYAML", "6.0", ["yaml"])}
        assert import_name_index(packages) == {"yaml": "pyyaml"}

    def test_real_environment_resolves_a_known_alias(self):
        index = import_name_index(installed_packages())
        # If PyYAML is installed, `yaml` must map back to it.
        if "yaml" in index:
            assert index["yaml"] == "pyyaml"
