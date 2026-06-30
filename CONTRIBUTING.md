# Contributing

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
make install          # editable install + dev/tui extras + pre-commit hook
make test             # run the suite
make lint             # ruff + mypy (matches CI)
```

If you don't use `make`:

```bash
pip install -e ".[dev,tui]"
pytest
ruff check src tests && ruff format --check src tests && mypy
```

## Common tasks

**Add or update a Defender setting.** Don't hand-edit anything — run
`mde-builder --refresh-schema` (or `make refresh-schema`). The setting surface
comes straight from Microsoft's published schema. If a brand-new top-level
section appears, add a line to `tests/test_schema.py`.

**Add a supporting (Apple approval) profile.** Drop a YAML file in
`src/mdebuilder/data/supporting/`. It's picked up automatically; the file's
`payloads:` list is rendered verbatim into a `.mobileconfig`.

**Add a Device Control scenario.** Add a `scenario_*` builder in
`src/mdebuilder/devicecontrol.py`, wire it into `interactive_device_control`,
and cover it in `tests/test_devicecontrol.py`.

**Keep an org baseline.** Run an interactive build, then copy the saved
`build/last_build.yaml` into `examples/baselines/` (or your own repo) under a
descriptive name and commit it. The baseline is the reviewable artefact;
profiles regenerate from it deterministically.

## Conventions

- Code is formatted and linted with **ruff**; type-checked with **mypy**.
  `pre-commit` runs these on commit.
- Keep static MDM values (bundle IDs, code requirements) in the supporting YAML,
  not in code, and link the Microsoft doc you sourced them from.
- Never split the `com.microsoft.wdav` domain beyond the `wdav` + `wdav.ext`
  pair — macOS merges duplicate identifiers unreliably. See
  [docs/architecture.md](docs/architecture.md).
