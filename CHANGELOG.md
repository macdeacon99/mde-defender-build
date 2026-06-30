# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-30

### Added
- Schema-driven interactive builder for `com.microsoft.wdav` settings. The
  policy surface (10 sections) is read from Microsoft's published
  `schema.json`, so it stays current via `--refresh-schema`.
- Supporting Apple approval profiles as editable YAML: system extensions,
  network content filter, Full Disk Access, notifications, background services.
- Device Control support: guided scenarios, JSON import, and automatic wiring of
  the `DC_in_dlp` feature flag plus Full Disk Access for `com.microsoft.dlp.daemon`.
- Smart profile splitting by payload domain (`concern`, default), isolating
  Device Control into a `com.microsoft.wdav.ext` profile; plus a `single`
  combined strategy.
- Reproducible baseline YAML (`save`/`load`) for GitOps review.
- `--validate` (plutil on macOS, plistlib everywhere) and `--list`.
- Test suite (pytest), linting/formatting (ruff), typing (mypy), GitHub Actions
  CI matrix, and a scheduled schema-refresh workflow.
