"""Config loading. Deliberately uses the SAFE yaml entry point.

PyYAML is installed and imported, so every version-matching scanner flags
CVE-2020-14343 here. But that advisory only affects yaml.load/full_load, and
this module calls safe_load - so pyvulncheck reports it as not reachable.
"""

import yaml


def load_settings(path: str) -> dict:
    with open(path) as handle:
        return yaml.safe_load(handle)
