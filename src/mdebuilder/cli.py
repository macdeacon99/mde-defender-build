#!/usr/bin/env python3
"""
MDE macOS Configuration Builder - command-line interface.

Interactive builder for Microsoft Defender for Endpoint macOS configuration
profiles, driven by Microsoft's own published schema so the policy surface is
always current.

Entry points:
    mde-builder ...            (installed console script)
    python -m mdebuilder ...   (module form)
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from . import devicecontrol, prompts
from .baselines import baseline_to_settings, load_baseline, save_baseline
from .profile import emit
from .schema import ArraySetting, SchemaModel, Setting, load_schema, refresh_schema
from .supporting import build_supporting, list_supporting, load_supporting_payloads

# Output and baselines are resolved relative to the current working directory,
# so the tool behaves predictably when run from a repo checkout.
DEFAULT_OUT = Path("build")
DEFAULT_EXAMPLE_BASELINE = "examples/baselines/example_recommended.yaml"


def banner(model: SchemaModel) -> None:
    print("=" * 64)
    print(" Microsoft Defender for Endpoint - macOS config builder")
    print(f" Schema version: {model.version}")
    if not prompts.have_questionary():
        print(" (install the 'tui' extra for a nicer interactive UI)")
    print("=" * 64)


def collect_array_setting(setting: ArraySetting) -> list:
    print(f"\n  {setting.title} ({setting.dotted})")
    if setting.description:
        print(f"    \u2139  {setting.description}")
    entries: list = []
    while prompts.confirm(f"    Add an entry to '{setting.title}'?", default=False):
        if setting.item_kind == "string":
            entries.append(prompts.text("      value"))
        else:
            entry = {}
            for field, spec in setting.item_properties.items():
                val = prompts.text(f"      {spec.get('title', field)} ({field})")
                if val != "":
                    entry[field] = val
            if entry:
                entries.append(entry)
    return entries


def interactive_build(model: SchemaModel, preset: dict | None = None):
    """Return (flat_wdav_settings, supporting_keys, metadata, device_control, strategy)."""
    flat: dict = {}
    preset_settings = (preset or {}).get("wdav_settings", {})

    sectionable = [s for s in model.sections if s != "deviceControl"]
    section_labels = [f"{s}  ({model.section_title(s)})" for s in sectionable]
    chosen_labels = prompts.checkbox(
        "Which Defender setting sections do you want to manage?",
        section_labels,
        preselected=[
            lbl
            for lbl, s in zip(section_labels, sectionable)
            if any(k.startswith(s + ".") for k in preset_settings)
        ],
    )
    chosen_sections = [sectionable[section_labels.index(lbl)] for lbl in chosen_labels]

    for section in chosen_sections:
        print(f"\n--- {model.section_title(section)} ---")
        for setting in model.settings_for(section):
            if isinstance(setting, ArraySetting):
                entries = collect_array_setting(setting)
                if entries:
                    flat[setting.dotted] = entries
                continue
            preselected = setting.dotted in preset_settings
            if prompts.confirm(
                f"Manage '{setting.title}' ({setting.dotted})?", default=preselected
            ):
                if preselected and isinstance(setting, Setting):
                    setting.default = preset_settings[setting.dotted]
                flat[setting.dotted] = prompts.ask_value(setting)

    print("\n--- Device Control ---")
    device_control = devicecontrol.interactive_device_control((preset or {}).get("device_control"))

    print("\n--- Supporting Apple approval profiles ---")
    supporting = list_supporting()
    sup_labels = [f"{s['key']}  ({s['name']})" for s in supporting]
    preselected_sup = [
        lbl
        for lbl, s in zip(sup_labels, supporting)
        if s["key"] in (preset or {}).get("supporting_profiles", [])
    ] or sup_labels
    chosen_sup_labels = prompts.checkbox(
        "Which supporting profiles to generate? (sysext/FDA/etc. are normally all required)",
        sup_labels,
        preselected=preselected_sup,
    )
    chosen_sup = [supporting[sup_labels.index(lbl)]["key"] for lbl in chosen_sup_labels]

    print("\n--- Profile split ---")
    strat_choice = prompts.select(
        "How should the profiles be split?",
        [
            "By concern (recommended) - one profile per payload domain",
            "Single combined profile - everything in one .mobileconfig",
        ],
    )
    strategy = "single" if strat_choice.startswith("Single") else "concern"

    pm = (preset or {}).get("metadata", {})
    print("\n--- Profile metadata ---")
    org = prompts.text("Organisation name", default=pm.get("organisation", "Example Org"))
    prefix = prompts.text(
        "Payload identifier prefix (reverse-DNS)",
        default=pm.get("identifier_prefix", "com.example.mde"),
    )
    name = prompts.text("Baseline name", default=pm.get("name", "Custom baseline"))

    meta = {
        "name": name,
        "schema_version": model.version,
        "organisation": org,
        "identifier_prefix": prefix,
    }
    return flat, chosen_sup, meta, device_control, strategy


def generate(flat, supporting, meta, out_dir, *, device_control=None, strategy="concern"):
    out_dir.mkdir(parents=True, exist_ok=True)
    settings = baseline_to_settings(flat)
    if device_control is not None:
        devicecontrol.wire_into_settings(settings, device_control)

    org = meta.get("organisation", "Example Org")
    prefix = meta.get("identifier_prefix", "com.example.mde")

    supporting_payloads = []
    if strategy == "single":
        for key in supporting:
            supporting_payloads += load_supporting_payloads(
                key, organisation=org, identifier_prefix=prefix
            )

    written = emit(
        settings,
        out_dir,
        organisation=org,
        identifier_prefix=prefix,
        strategy=strategy,
        supporting_payloads=supporting_payloads,
        device_control_policy=device_control,
    )

    if strategy == "concern":
        for i, key in enumerate(supporting, start=3):
            p = build_supporting(key, out_dir, organisation=org, identifier_prefix=prefix)
            ordered = out_dir / f"MDE-{i:02d}-{key}.mobileconfig"
            p.rename(ordered)
            written.append(ordered)
    return written


def validate(out_dir: Path) -> int:
    """Lint generated plists. Uses plutil on macOS; always re-parses with plistlib."""
    import plistlib

    files = sorted(out_dir.glob("*.mobileconfig")) + sorted(out_dir.glob("*.plist"))
    if not files:
        print(f"No profiles found in {out_dir}.")
        return 1
    plutil = shutil.which("plutil")
    ok = True
    for f in files:
        try:
            with f.open("rb") as fh:
                plistlib.load(fh)
        except Exception as exc:  # noqa: BLE001
            print(f"  FAIL (parse) {f.name}: {exc}")
            ok = False
            continue
        if plutil:
            r = subprocess.run([plutil, "-lint", str(f)], capture_output=True, text=True)
            print(f"  {'OK' if r.returncode == 0 else 'FAIL'} (plutil) {f.name}")
            ok = ok and r.returncode == 0
        else:
            print(f"  OK (plistlib) {f.name}")
    dc = out_dir / "device_control_policy.json"
    if dc.exists():
        print(f"\n  Device Control JSON present: {dc.name}")
        print(f"    mdatp device-control policy validate --path {dc}")
    if not plutil:
        print("\n  (plutil not found - run --validate on macOS for full lint)")
    return 0 if ok else 1


def do_list(model: SchemaModel) -> None:
    print(f"Schema version {model.version}\n")
    print("Setting sections (com.microsoft.wdav):")
    for s in model.sections:
        n = len(model.settings_for(s))
        extra = "  [own Device Control flow]" if s == "deviceControl" else ""
        print(f"  {s} ({model.section_title(s)}) - {n} settings{extra}")
    print("\nSupporting profiles:")
    for sp in list_supporting():
        print(f"  {sp['key']} - {sp['name']}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="mde-builder", description="Build Microsoft Defender macOS config profiles."
    )
    ap.add_argument(
        "--refresh-schema", action="store_true", help="Download the latest schema from Microsoft."
    )
    ap.add_argument(
        "--from-baseline", type=Path, help="Build non-interactively from a baseline YAML."
    )
    ap.add_argument(
        "--out", type=Path, default=DEFAULT_OUT, help="Output directory (default: ./build)."
    )
    ap.add_argument("--split", choices=["concern", "single"], help="Override split strategy.")
    ap.add_argument(
        "--list", action="store_true", help="List sections + supporting profiles, then exit."
    )
    ap.add_argument("--validate", action="store_true", help="Lint profiles in --out and exit.")
    ap.add_argument(
        "--save-baseline", type=Path, help="Where to write the baseline from an interactive run."
    )
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.refresh_schema:
        try:
            print(f"Schema refreshed to version {refresh_schema()}.")
        except Exception as exc:  # noqa: BLE001
            print(f"Could not refresh schema: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.validate:
        return validate(args.out)

    try:
        model = SchemaModel(load_schema())
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1

    if args.list:
        do_list(model)
        return 0

    if args.from_baseline:
        doc = load_baseline(args.from_baseline)
        flat = doc.get("wdav_settings", {})
        supporting = doc.get("supporting_profiles", [])
        meta = doc.get("metadata", {})
        meta.setdefault("organisation", "Example Org")
        meta.setdefault("identifier_prefix", "com.example.mde")
        strategy = args.split or meta.get("split_strategy", "concern")
        dc = doc.get("device_control")
        written = generate(flat, supporting, meta, args.out, device_control=dc, strategy=strategy)
        print(f"\nGenerated {len(written)} file(s) in {args.out} (split: {strategy}):")
        for p in written:
            print(f"  {p.name}")
        return 0

    banner(model)
    preset = None
    if prompts.confirm("Start from an existing baseline file?", default=False):
        bpath = Path(prompts.text("Path to baseline YAML", default=DEFAULT_EXAMPLE_BASELINE))
        if bpath.exists():
            preset = load_baseline(bpath)
        else:
            print(f"  (not found: {bpath} - starting fresh)")

    flat, supporting, meta, dc, strategy = interactive_build(model, preset)
    if args.split:
        strategy = args.split
    written = generate(flat, supporting, meta, args.out, device_control=dc, strategy=strategy)

    bl_path = args.save_baseline or (args.out / "last_build.yaml")
    save_baseline(
        bl_path, meta=meta, wdav=flat, supporting=supporting, device_control=dc, strategy=strategy
    )

    print(f"\nGenerated {len(written)} file(s) in {args.out} (split: {strategy}):")
    for p in written:
        print(f"  {p.name}")
    print(f"\nBaseline saved to {bl_path} (copy into examples/baselines/ or your repo to keep it).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
