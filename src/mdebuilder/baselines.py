"""
A "baseline" is a reviewable YAML file capturing every decision: which wdav
settings to manage and their values, plus which supporting profiles to emit.

This is the bit that makes the tool fit a policy-as-code / GitOps workflow:
the baseline is the artefact you commit and review; the .mobileconfig files are
regenerated from it deterministically.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .profile import set_nested


def save_baseline(
    path: Path,
    *,
    meta: dict[str, Any],
    wdav: dict[str, list],
    supporting: list[str],
    device_control: dict[str, Any] | None = None,
    strategy: str = "concern",
) -> None:
    """
    wdav: mapping of dotted-path -> value (flat, easy to read in a diff)
    supporting: list of supporting profile keys to include
    device_control: optional Device Control policy (settings/groups/rules)
    strategy: profile split strategy ("concern" | "single")
    """
    meta = dict(meta)
    meta["split_strategy"] = strategy
    doc: dict[str, Any] = {
        "metadata": meta,
        "wdav_settings": dict(sorted(wdav.items())),
        "supporting_profiles": supporting,
    }
    if device_control is not None:
        doc["device_control"] = device_control
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(doc, sort_keys=False, default_flow_style=False), encoding="utf-8"
    )


def load_baseline(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def baseline_to_settings(flat: dict[str, Any]) -> dict[str, Any]:
    """Expand a flat {dotted.path: value} map into the nested wdav settings dict."""
    nested: dict[str, Any] = {}
    for dotted, value in flat.items():
        set_nested(nested, dotted.split("."), value)
    return nested
