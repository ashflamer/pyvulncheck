# Contributing

The most valuable contribution is a **curated advisory entry**. It is a single
small JSON file, it needs no Python, and it permanently improves every scan of
that package.

## Adding an advisory

1. Pick an advisory that `pyvulncheck` currently reports as `UNKNOWN`:

   ```bash
   pyvulncheck . --all | grep UNKNOWN
   ```

2. Open its fix commit (the advisory page on osv.dev links it) and read the
   diff. Note which functions actually changed.

3. Create `src/pyvulncheck/data/advisories/<ADVISORY-ID>.json` following the schema in
   [`src/pyvulncheck/data/advisories/README.md`](src/pyvulncheck/data/advisories/README.md).

4. Validate and test:

   ```bash
   python scripts/validate_dataset.py
   pytest
   ```

5. Open a PR. In the description, link the fix commit and say in one line why
   those symbols and not others.

### What makes a good entry

- **List what the fix changed, not what the module contains.** One function
  patched means one symbol.
- **Exclude functions that were never vulnerable.** The PyYAML entry omits
  `yaml.safe_load` on purpose — that omission is the entire value of the entry.
- **Prefer the deepest honest symbol.** Naming a wrapper everything calls turns
  the advisory back into noise.
- **Explain yourself in `notes`.** A future reader should be able to disagree
  with you using your own reasoning.

## Code changes

```bash
pip install -e ".[dev]"
pytest
```

House rules:

- **No runtime dependencies.** Standard library only. Test-only dependencies
  are fine.
- **No network in tests.** Capture a real response into `tests/fixtures/` and
  use the `no_network` fixture.
- **Never report `NOT_REACHABLE` without evidence.** If the analysis could not
  determine something, the answer is `UNKNOWN` or `POSSIBLE`. A false sense of
  safety is the one bug this project cannot ship.
- New behaviour needs a test that would fail without it.
