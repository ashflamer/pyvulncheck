# Curated vulnerable-symbol dataset

Each file maps one advisory to the **specific functions** that make it
dangerous. This is the data OSV ships for Go and does not ship for PyPI, and
it is the single most valuable thing you can contribute to this project.

## Schema

| field | required | meaning |
|---|---|---|
| `schema_version` | yes | currently `"1.0"` |
| `id` | yes | the OSV/GHSA id; must match the filename |
| `aliases` | no | CVE and PYSEC ids, so lookups work either way |
| `package` | yes | PyPI distribution name, normalised (PEP 503) |
| `ecosystem` | yes | always `"PyPI"` |
| `symbols` | yes | fully qualified vulnerable functions |
| `notes` | yes | why these symbols, and what reachability means here |
| `fix_commits` | no | links that justify the symbol list |
| `safe_wrappers` | no | entry points that reach a vulnerable symbol internally but are *not* a route to the bug |
| `reviewed` | yes | `true` once a human has checked the fix diff |
| `reviewer_note` | no | anything surprising a future reader should know |

## Writing `symbols`

Use the import path a caller would actually use:

```
jinja2.filters.do_xmlattr                 module-level function
requests.sessions.Session.rebuild_proxies method on a class
yaml.loader.FullLoader                    a class used as an argument
```

Capitalised components are treated as class names, so
`a.b.Klass.method` is read as module `a.b`, symbol `Klass.method`.

## `safe_wrappers`

Libraries often route their safe API through their unsafe one. PyYAML's
`safe_load()` calls `load()` with `SafeLoader`, so a call-graph walk finds a
path from any project using the documented safe function straight to the
vulnerable symbol.

Listing the safe entry point here tells the analyser that crossing into the
package at that function is not a route to the bug:

```json
"symbols": ["yaml.load", "yaml.full_load"],
"safe_wrappers": ["yaml.safe_load", "yaml.safe_load_all"]
```

Without it the finding degrades to `POSSIBLE` rather than being suppressed —
the tool never guesses in the unsafe direction, but it stays noisier than it
needs to be. This field is often the single highest-value line in an entry.

## Rules

1. **List what the fix changed, not what the module contains.** If the patch
   touched one function, the list has one entry.
2. **Exclude functions that were never vulnerable.** `yaml.safe_load` is not
   on the PyYAML entry above, and that omission is the whole point.
3. **Prefer the deepest honest symbol.** Naming a wrapper that everything
   calls turns the advisory into noise again.
4. **Read the diff before setting `reviewed: true`.** Automatic derivation
   already handles the easy cases; curated entries exist to be better.
