# Example: the same project, two very different answers

Five outdated pins in `requirements.txt`. A version-range scanner reports
every advisory that touches them. `pyvulncheck` sorts them by whether this
code can actually reach the vulnerable function.

```console
$ pyvulncheck examples/vulnerable-app
...
17 advisories affect installed packages. 6 need attention.
```

What each module demonstrates:

| file | demonstrates |
|---|---|
| `app/templating.py` | **REACHABLE** — calls `jinja2.filters.do_xmlattr` directly |
| `app/views.py` | the entry point the reported call path starts from |
| `app/config.py` | the wrapper problem — uses `yaml.safe_load`, never `yaml.load` |
| `app/client.py` | **POSSIBLE** — `parser.parse(...)` on a receiver that can't be resolved |

## The interesting one

`app/config.py` calls only `yaml.safe_load`, which was never vulnerable. But
inside PyYAML, `safe_load()` calls `load()` with `SafeLoader` — so following
the call graph into the dependency finds a path from this app to the
vulnerable symbol.

Three PyYAML advisories, three different answers, driven entirely by how good
the symbol data is:

- **CVE-2020-14343** — curated entry lists `yaml.safe_load` under
  `safe_wrappers` → correctly suppressed as *not reachable*.
- **CVE-2020-1747** — no curated entry, symbols derived from the fix commit →
  reported `POSSIBLE`, because the tool will not claim safety it cannot prove
  and will not claim `REACHABLE` through a wrapper it cannot analyse.
- **CVE-2019-20477** — no symbol data at all → `UNKNOWN`.

Curating one more advisory moves a finding from the middle column to a
definite answer. That is the whole contribution loop.

## Reproducing it

The verdicts depend on which versions are actually installed:

```bash
pip install "jinja2==3.1.2" "werkzeug==2.2.2" "pyyaml==5.1"
pyvulncheck examples/vulnerable-app
```

To audit the pins without installing them:

```bash
pyvulncheck examples/vulnerable-app -r examples/vulnerable-app/requirements.txt
```
