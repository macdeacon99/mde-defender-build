# MDE macOS Configuration Builder

An interactive CLI that builds Microsoft Defender for Endpoint (MDE)
configuration profiles for macOS — the Defender equivalent of what the macOS
Security Compliance Project (mSCP) does for CIS/NIST mobileconfigs.

Runs on **macOS, Windows and Linux** (Python 3.9+). The only hard dependency is
PyYAML; the optional `tui` extra (`questionary`) adds an arrow-key UI.

[![CI](https://github.com/your-org/mde-config-builder/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/mde-config-builder/actions/workflows/ci.yml)

---

## Why it's built this way

mSCP hand-authors one YAML rule per control. For Defender that's the wrong call,
because Microsoft publishes a **versioned JSON schema** of every configurable
`com.microsoft.wdav` setting. This tool reads that schema as the source of truth
and walks it to drive the prompts — `--refresh-schema` pulls the latest with no
code change. The supporting Apple approval profiles (not in the schema) are a
small editable YAML set, and your choices save to a reviewable **baseline YAML**
that profiles regenerate from deterministically.

Full reasoning, including the macOS profile-split constraint and Device Control
wiring, is in [docs/architecture.md](docs/architecture.md).

---

## Install

```bash
git clone <repo-url> && cd mde-config-builder
make install                       # editable install + dev/tui extras + hooks
# or, without make:
pip install -e ".[tui]"            # add ".[dev]" for tests/lint
```

## Use

```bash
mde-builder                                  # interactive build
mde-builder --list                           # all sections + supporting profiles
mde-builder --refresh-schema                 # pull latest schema from Microsoft
mde-builder --from-baseline examples/baselines/example_recommended.yaml
mde-builder --from-baseline examples/baselines/example_devicecontrol.yaml
mde-builder --validate --out build           # lint output (plutil on macOS)
mde-builder --split single                   # override the split strategy
```

`python -m mdebuilder ...` works identically. Output lands in `./build/`.

---

## Profile splitting

You **cannot** freely split `com.microsoft.wdav` into category profiles — macOS
merges duplicate-identifier profiles unreliably (it keeps one at random). The
correct split is **by Apple payload domain**, which is also Apple best practice.

- **`concern` (default):** one profile per payload domain, numbered for deploy
  order. Defender's behavioural settings stay in one `com.microsoft.wdav`
  profile; Device Control + its DLP flag are isolated into a
  `com.microsoft.wdav.ext` profile.

  ```
  MDE-01-defender-settings.mobileconfig    com.microsoft.wdav
  MDE-02-device-control.mobileconfig       com.microsoft.wdav.ext
  MDE-03-system_extensions.mobileconfig    com.apple.system-extension-policy
  MDE-04-network_filter.mobileconfig       com.apple.webcontent-filter
  MDE-05-full_disk_access.mobileconfig     com.apple.TCC.configuration-profile-policy
  MDE-06-notifications.mobileconfig        com.apple.notificationsettings
  MDE-07-background_services.mobileconfig  com.apple.servicemanagement
  com.microsoft.wdav.plist / .ext.plist    inner dicts for Jamf "Upload PLIST File"
  device_control_policy.json               raw policy for `mdatp ... validate`
  ```

- **`single`:** everything in one `MDE-combined.mobileconfig` (testing only).

---

## Device Control

A JSON policy (`settings`/`groups`/`rules`) carried under `deviceControl.policy`.
The tool wires the three things needed to make it enforce: the policy, the
`dlp` `DC_in_dlp` flag, and Full Disk Access for `com.microsoft.dlp.daemon`.
Guided scenarios (block/read-only/allow-approved-USB/audit/block-Apple/portable)
or import your own JSON. Always validate on an onboarded Mac:

```bash
mdatp device-control policy validate --path build/device_control_policy.json
```

---

## Development

```bash
make test     # pytest (also runs in CI on Linux/macOS/Windows, py3.9-3.12)
make lint     # ruff check + ruff format --check + mypy
make format   # auto-fix
```

CI (`.github/workflows/ci.yml`) runs lint + the test matrix on every push/PR.
A scheduled workflow (`schema-refresh.yml`) refreshes the Microsoft schema
weekly and opens a PR when it changes. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Deployment notes (read before production)

- **Onboarding is separate** — deploy `WindowsDefenderATPOnboarding.plist` under
  the `com.microsoft.wdav.atp` domain yourself.
- **One profile per identifier** — never hand-split `com.microsoft.wdav` beyond
  the `wdav` + `wdav.ext` pair the tool uses.
- **Re-verify static values** in `src/mdebuilder/data/supporting/*.yaml` against
  current Microsoft docs (<https://learn.microsoft.com/en-us/defender-endpoint/mac-sysext-policies>).
- **Sign** the profiles if your posture requires it (emitted unsigned).
- **Deploy order:** sysext → network filter → FDA → notifications/background →
  `com.microsoft.wdav` → Device Control (`.ext`) → onboarding (the `MDE-NN-`
  prefixes encode this).

---

## Layout

```
pyproject.toml            packaging, deps, console script, ruff/mypy/pytest config
Makefile                  install / lint / test / run helpers
src/mdebuilder/
  cli.py                  argparse entry point + interactive flow
  schema.py               loads + walks Microsoft's schema.json
  prompts.py              interactive prompts (questionary, stdlib fallback)
  profile.py              mobileconfig assembly + split strategies (plistlib)
  devicecontrol.py        Device Control policy builders / scenarios / import
  supporting.py           builds supporting profiles from YAML
  baselines.py            save/load reviewable baseline YAML
  data/
    schema.json           cached Microsoft schema (refreshable)
    supporting/*.yaml     Apple approval profiles
examples/baselines/*.yaml example baselines to start from
tests/                    pytest suite
docs/architecture.md      design decisions
.github/workflows/        CI + scheduled schema refresh
```
