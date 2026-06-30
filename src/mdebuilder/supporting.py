"""
The com.microsoft.wdav schema covers Defender's *behaviour*, but a working
deployment also needs Apple-side approval profiles that are NOT in that schema:
system extension allow-listing, the network content filter, Full Disk Access
(TCC/PPPC), notifications and managed login items.

These have fixed, well-known values (Microsoft Team ID UBF8T346G9 and a small
set of bundle identifiers / code requirements). We keep them as editable YAML
under data/supporting/ rather than burying them in code, so they can be audited
and version-bumped without touching the program.

IMPORTANT: code requirements and bundle IDs should be re-verified against the
current Microsoft docs at deploy time:
  https://learn.microsoft.com/en-us/defender-endpoint/mac-sysext-policies
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .profile import _new_uuid, wrap_profile, write_plist

SUPPORTING_DIR = Path(__file__).resolve().parent / "data" / "supporting"


def list_supporting() -> list[dict[str, Any]]:
    """Return metadata for every supporting profile YAML found."""
    items = []
    for f in sorted(SUPPORTING_DIR.glob("*.yaml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        items.append(
            {
                "key": f.stem,
                "name": doc.get("name", f.stem),
                "description": doc.get("description", ""),
                "file": f,
            }
        )
    return items


def load_supporting_payloads(
    key: str, *, organisation: str, identifier_prefix: str
) -> list[dict[str, Any]]:
    """Return the raw payload dicts for a supporting profile (for 'single' split)."""
    path = SUPPORTING_DIR / f"{key}.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    payloads: list[dict[str, Any]] = []
    for p in doc.get("payloads", []):
        payload = dict(p)
        payload.setdefault("PayloadVersion", 1)
        payload.setdefault("PayloadEnabled", True)
        payload.setdefault("PayloadUUID", _new_uuid())
        payload.setdefault("PayloadIdentifier", f"{identifier_prefix}.{key}.{len(payloads)}")
        payload.setdefault("PayloadOrganization", organisation)
        payloads.append(payload)
    return payloads


def build_supporting(key: str, out_dir: Path, *, organisation: str, identifier_prefix: str) -> Path:
    """Render one supporting profile YAML into a .mobileconfig."""
    path = SUPPORTING_DIR / f"{key}.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))

    payloads: list[dict[str, Any]] = []
    for p in doc.get("payloads", []):
        payload = dict(p)  # copy the YAML-defined body verbatim
        payload.setdefault("PayloadVersion", 1)
        payload.setdefault("PayloadEnabled", True)
        payload.setdefault("PayloadUUID", _new_uuid())
        payload.setdefault("PayloadIdentifier", f"{identifier_prefix}.{key}.{len(payloads)}")
        payload.setdefault("PayloadOrganization", organisation)
        payloads.append(payload)

    profile = wrap_profile(
        payloads,
        display_name=doc.get("name", key),
        description=doc.get("description", ""),
        identifier=f"{identifier_prefix}.{key}",
        organisation=organisation,
    )
    out = out_dir / f"{key}.mobileconfig"
    write_plist(profile, out)
    return out
