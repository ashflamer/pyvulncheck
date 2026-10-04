# pyvulncheck

**Reachability-based vulnerability triage for Python.** Not *"is a vulnerable
version installed?"* but *"does a call path exist from my code to the
vulnerable function?"*

[![CI](https://github.com/ashflamer/pyvulncheck/actions/workflows/ci.yml/badge.svg)](https://github.com/ashflamer/pyvulncheck/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Zero dependencies](https://img.shields.io/badge/runtime%20deps-0-brightgreen)](pyproject.toml)

---

## The problem

Point any scanner at a project with five outdated pins and you get dozens of
advisories. Almost none of them matter, because almost none of the vulnerable
*functions* are ever called. Teams learn to dismiss the whole feed — one study
of automated security PRs found roughly **85% are closed without being merged**.

Go solved this. `govulncheck` reports a vulnerability only when it can trace a
call path to the affected symbol. It can do that because the Go vulnerability
database publishes the vulnerable symbols:

```jsonc
// osv.dev/vulnerability/GO-2023-1570
"ecosystem_specific": {
  "imports": [{
    "path": "crypto/tls",
    "symbols": ["Conn.Handshake", "Conn.Read", "Conn.clientHandshake", ...]
  }]
}
```

Here is the same field on a PyPI advisory:

```jsonc
// osv.dev/vulnerability/GHSA-h5c8-rqwp-cp95  (jinja2, CVE-2024-22195)
"ecosystem_specific": {}
```

Empty. **No PyPI advisory carries symbol-level data**, which is why Python has
version-range matchers (`pip-audit`, Safety, Dependabot) and no reachability
tool. There is a test in this repo asserting that emptiness; if OSV ever fixes
it, the suite goes red and that will be excellent news.

## The idea

The data isn't published, but it is *recoverable*. Every advisory links its own
fix commit, and git puts the enclosing function in every hunk header:

```diff
--- a/src/jinja2/filters.py
+++ b/src/jinja2/filters.py
@@ -273,12 +277,22 @@ def do_xmlattr(
```

`src/jinja2/filters.py` + `def do_xmlattr(` = `jinja2.filters.do_xmlattr`.
The function the maintainer patched *is* the vulnerable function. That one
inference is the missing middle, and it's what this tool is built on.

## Install

```bash
pip install pyvulncheck            # once published
pip install git+https://github.com/ashflamer/pyvulncheck
```

Python 3.9+, **zero runtime dependencies** — stdlib `urllib` and `ast` only. A
security tool shouldn't widen your dependency tree to run.

## Use

```bash
pyvulncheck .                                   # scan the current project
pyvulncheck . -r requirements.txt               # audit a requirements file
pyvulncheck . --all                             # include unreachable findings
pyvulncheck . --format sarif -o out.sarif       # GitHub code scanning
pyvulncheck . --offline                         # cache only, no network
```

### Real output

Running against [`examples/vulnerable-app`](examples/vulnerable-app) — five
outdated pins, four source files:

```console
$ pyvulncheck examples/vulnerable-app
Scanned 4 files, 6 installed packages, 17 advisories.

Vulnerabilities your code can reach (2)

  REACHABLE  Jinja2 3.1.2 → 3.1.3  CVE-2024-22195  MODERATE
    Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter
    symbols from the curated dataset
    examples/vulnerable-app/app/templating.py:11
      app.templating.render_tag → jinja2.filters.do_xmlattr
    examples/vulnerable-app/app/views.py:7
      app.views.widget_view → app.templating.render_tag → jinja2.filters.do_xmlattr

Possibly reachable (receiver could not be resolved) (4)

  POSSIBLE  PyYAML 5.1 → 5.3.1  CVE-2020-1747  CRITICAL
    Improper Input Validation in PyYAML
    symbols derived from the fix commit
    examples/vulnerable-app/app/config.py:11
      app.config.load_settings → yaml.safe_load → yaml.load

  POSSIBLE  Werkzeug 2.2.2 → 2.2.3  CVE-2023-25577  HIGH
    High resource usage when parsing multipart form data with many fields
    symbols from the curated dataset
    app.client.handle (unresolved receiver)

No symbol data - reachability unknown (1)

  UNKNOWN  PyYAML 5.1 → 5.2  CVE-2019-20477  CRITICAL
    Deserialization of Untrusted Data in PyYAML
    no vulnerable-symbol data for this advisory; package is imported

17 advisories affect installed packages. 6 need attention.
11 had no reachable call path and were hidden (use --all to list them).
```

**17 advisories. 6 need attention.** And the ones that matter come with the
exact line to look at.

### What the PyYAML results show

Three advisories against one installed package, answered three different ways
depending on how good the symbol data is. This is the clearest illustration of
why the curated dataset is worth contributing to:

| CVE | symbol data | verdict |
|---|---|---|
| CVE-2020-14343 | curated, with `safe_wrappers` | `not reachable` |
| CVE-2020-1747 | derived from the fix commit | `POSSIBLE` |
| CVE-2019-20477 | none | `UNKNOWN` |

The app only ever calls `yaml.safe_load`, which was never vulnerable. But
inside PyYAML, `safe_load()` calls `load()` with `SafeLoader` — so a naive
call-graph walk "proves" that every project using the *documented safe API*
reaches the vulnerable symbol. Getting that wrong would discredit the tool, so:

- the **curated** entry for CVE-2020-14343 lists `yaml.safe_load` under
  `safe_wrappers`, and the finding is correctly suppressed with the reason
  *"only reached through yaml.safe_load, which this advisory's curated entry
  records as a safe wrapper"*;
- CVE-2020-1747 has no curated entry, so the tool will not claim safety — but
  it also refuses to claim `REACHABLE`, reporting `POSSIBLE` with the reason
  *"reached only indirectly, via yaml.safe_load inside PyYAML; the wrapper may
  constrain the vulnerable argument"*.

The general rule: **an advisory's symbol list describes a public API
boundary.** What matters is the function *your* code calls to enter the
package, not how the package routes internally afterwards.

## The four verdicts

| verdict | meaning | act on it? |
|---|---|---|
| `REACHABLE` | a resolved call path exists, and it's printed for you | **yes** |
| `POSSIBLE` | you call a matching method name on a receiver that couldn't be resolved — duck typing, a factory, a plugin registry | **yes, briefly** |
| `UNKNOWN` | no symbol data for this advisory; the package *is* imported | treat as unresolved |
| `NOT_REACHABLE` | no static path found | deprioritise — **not** a proof of safety |

Four verdicts rather than two is a deliberate choice. Python is dynamically
typed; a sound call graph is impossible. Collapsing `POSSIBLE` into "safe"
would make the tool more satisfying and less honest.

## How it works

```
installed packages ──► OSV.dev ──► advisories
                                      │
                                      ▼
                            symbol resolution
                      ┌───────────────┼───────────────┐
                 1. curated      2. derived        3. none
                 (data/*.json)   (fix commit)    (→ UNKNOWN)
                                      │
                                      ▼
   your source + affected dependency source ──► AST call graph
                                      │
                                      ▼
                     reverse BFS from vulnerable symbols
                                      │
                                      ▼
                            verdict + call path
```

**Three-tier symbol resolution.** Curated entries in
[`src/pyvulncheck/data/advisories/`](src/pyvulncheck/data/advisories/) come first; anything uncurated falls back
to parsing the fix commit; anything left reports `UNKNOWN` rather than guessing.
Every finding states which tier it came from.

**The call graph spans your code *and* your dependencies.** Python ships real
source in site-packages — an advantage over compiled ecosystems — so a path can
run `your_view → library_helper → vulnerable_function`. Only packages that
actually carry advisories get parsed, so cost scales with risk, not with the
size of your virtualenv.

**The search runs backwards.** Forward BFS from every function explores a huge
space to mostly prove nothing. Reverse BFS from each vulnerable symbol touches
only the relevant subgraph, and the predecessor map hands back the call path for
free.

| module | responsibility |
|---|---|
| `osv.py` | OSV.dev client, on-disk cache, advisory parsing |
| `discovery.py` | installed distributions, dist-name → import-name mapping |
| `symbols.py` | the three-tier resolver and the patch parser |
| `callgraph.py` | AST → definitions, call edges, unresolved calls |
| `reachability.py` | reverse BFS, the four verdicts |
| `report.py` | text / JSON / SARIF, CI exit codes |

## CI

```yaml
- run: pip install pyvulncheck
- run: pyvulncheck . --format sarif --output pyvulncheck.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pyvulncheck.sarif
```

Exit codes: `0` nothing at or above the threshold, `1` threshold met, `2` the
scan failed. Default threshold is `REACHABLE`; tighten with
`--fail-on possible`.

## Limitations

Read this section before trusting a green result.

- **`NOT_REACHABLE` is not a proof of safety.** It means *this* analysis found
  no static path. `getattr`, `eval`, entry points, signals, template rendering,
  metaclasses, C extensions and monkey-patching all defeat static analysis.
- **Reflection and dynamic dispatch are invisible.** That's what `POSSIBLE`
  exists for, and it only fires on a matching method name.
- **Derived symbols over-approximate.** A fix commit may touch adjacent
  functions; the derived list can name functions that weren't vulnerable.
  Over-approximation is the safe direction, and curated entries fix it properly.
- **Data flow is not analysed.** Reaching `do_xmlattr` isn't the same as
  reaching it *with attacker-controlled input*. That judgement is still yours.
- **Only the import graph of code you scan is considered.** Vulnerabilities
  triggered purely through configuration or data files won't be found.

The tool is built to shorten your triage queue, not to replace your judgement.

## Contributing

**The curated dataset is where contributions matter most.** One advisory file
makes every future scan of that package sharper for everyone. The schema is
documented in [`src/pyvulncheck/data/advisories/README.md`](src/pyvulncheck/data/advisories/README.md) and
validated in CI:

```bash
python scripts/validate_dataset.py
```

A good entry names only the functions the fix actually changed, and explains in
`notes` what reachability means for that CVE.

## Development

```bash
git clone https://github.com/ashflamer/pyvulncheck
cd pyvulncheck
pip install -e ".[dev]"
pytest                          # 181 tests, fully offline
```

The suite never touches the network — real OSV responses and a real fix patch
are committed as fixtures in `tests/fixtures/`, and a `no_network` fixture makes
any accidental `urlopen` call fail loudly.

## Prior art

- **[govulncheck](https://go.dev/blog/vuln)** — the model this follows. Possible
  in Go because the vulnerability database publishes symbols.
- **[pip-audit](https://github.com/pypa/pip-audit)**, **Safety**, **Dependabot** —
  version-range matchers. Excellent at finding affected versions; they do not
  model your call graph.
- **[OSV.dev](https://osv.dev)** — the advisory source this builds on.

The gap this fills is narrow and specific: PyPI advisories lack the symbol data
that makes reachability analysis possible, and that data can be reconstructed
from the fix commits the advisories already link.

## License

MIT — see [LICENSE](LICENSE).
