"""pyvulncheck - does your code actually reach the vulnerable function?

Most Python vulnerability scanners answer "is a vulnerable version installed?".
That question produces so much noise that ~85% of automated security PRs are
never merged. Go solved this with govulncheck, which only reports a CVE when a
call path exists from your code to the vulnerable symbol.

Python cannot do that today because PyPI advisories carry no symbol data (the
`ecosystem_specific` field is empty, where Go's lists every affected function).
pyvulncheck fills that gap by deriving the vulnerable symbols from each
advisory's own fix commit, then proving or disproving reachability with a call
graph built over your code *and* your dependencies' source.
"""

__version__ = "0.1.0"

from pyvulncheck.models import (
    Advisory,
    Confidence,
    Finding,
    Reachability,
    VulnerableSymbol,
)

__all__ = [
    "Advisory",
    "Confidence",
    "Finding",
    "Reachability",
    "VulnerableSymbol",
    "__version__",
]
