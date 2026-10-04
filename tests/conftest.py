import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import pytest

FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture
def fixtures():
    return FIXTURES


@pytest.fixture
def jinja_patch():
    return (FIXTURES / "jinja_fix.patch").read_text()


@pytest.fixture
def curated_dir():
    return ROOT / "src" / "pyvulncheck" / "data" / "advisories"


@pytest.fixture
def no_network(monkeypatch):
    """Hard guarantee: any test touching urlopen fails loudly."""
    import urllib.request

    def explode(*args, **kwargs):
        raise AssertionError("test attempted a network call")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
