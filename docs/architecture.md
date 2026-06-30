# Architecture & design decisions

## 1. Schema-driven, not hand-authored rules

The macOS Security Compliance Project keeps one hand-written YAML rule per
control because CIS is a curated human standard. Defender is different:
Microsoft publishes a **versioned JSON schema** of every configurable
`com.microsoft.wdav` setting at
`microsoft/mdatp-xplat/macos/schema/schema.json`.

So the tool reads that schema as the source of truth and walks it to drive the
prompts (`schema.py`). New settings appear via `--refresh-schema` with no code
change. The scheduled `schema-refresh` workflow turns that into a reviewable PR.

The only hand-maintained data is the set of **Apple-side approval profiles**
(`data/supporting/*.yaml`) — system extensions, network filter, Full Disk
Access, notifications, login items. These aren't in Microsoft's schema, but
their values (Team ID `UBF8T346G9`, the `epsext`/`netext`/`dlp.daemon`
identifiers and code requirements) are fixed and well-known.

## 2. The profile-split constraint

macOS only merges duplicate-identifier configuration profiles at the **top
level**, and where the same section appears twice it keeps one at random and
ignores the rest. Microsoft's guidance is therefore: at most **one** profile per
`com.microsoft.wdav` identifier, with exactly one sanctioned escape hatch — the
`com.microsoft.wdav.ext` identifier — for a second profile.

Consequences encoded in `profile.py`:

- Defender behavioural settings are **never** fragmented across multiple
  `com.microsoft.wdav` profiles.
- The `concern` split puts those settings in one `com.microsoft.wdav` profile,
  and isolates Device Control + its `dlp` flag into a `com.microsoft.wdav.ext`
  profile (`split_settings()` partitions on `EXT_SECTIONS`).
- Everything else splits by **Apple payload domain** (different `PayloadType`s),
  which macOS merges safely and which mirrors deploy-order best practice. Files
  are numbered `MDE-NN-` to encode that order.
- `single` mode bundles every payload into one `.mobileconfig` — valid, but
  harder to scope; offered for testing/completeness only.

## 3. Device Control wiring

Device Control is a JSON policy (`settings`/`groups`/`rules`) carried under
`com.microsoft.wdav` → `deviceControl.policy`. Enabling it requires three
things, all handled by `devicecontrol.wire_into_settings()` and the FDA profile:

1. `deviceControl.policy` set to the policy,
2. the `dlp` `DC_in_dlp` feature flag (`enabled`),
3. Full Disk Access for `com.microsoft.dlp.daemon`.

The raw policy is also emitted as `device_control_policy.json` so it can be
validated on an onboarded Mac with `mdatp device-control policy validate`.

## 4. Baselines as the GitOps artefact

A run's choices serialise to a flat, sorted baseline YAML (`baselines.py`).
That file — not the generated `.mobileconfig`s — is what you commit and review;
profiles regenerate from it deterministically with
`mde-builder --from-baseline`.
