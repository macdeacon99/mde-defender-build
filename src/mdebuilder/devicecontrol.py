"""
Microsoft Defender Device Control for macOS.

Device Control is a JSON policy (settings / groups / rules) that lives inside
the com.microsoft.wdav preferences under deviceControl.policy. Enabling it also
requires the dlp "DC_in_dlp" feature flag and Full Disk Access for
com.microsoft.dlp.daemon (handled by the FDA supporting profile).

This module offers three ways to get a policy:
  1. import an existing, externally-validated policy JSON file;
  2. a guided builder for the common enterprise scenarios;
  3. a generic groups/rules builder.

Always validate the result on an onboarded Mac with:
    mdatp device-control policy validate --path <file.json>

Reference: https://learn.microsoft.com/en-us/defender-endpoint/mac-device-control-overview
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from . import prompts

PRIMARY_IDS = {
    "removable_media_devices": "Removable media (USB sticks, external drives)",
    "apple_devices": "Apple devices (iPhone/iPad)",
    "portable_devices": "Portable devices (cameras, PTP)",
    "bluetooth_devices": "Bluetooth media",
}
FEATURE_FOR_PRIMARY = {
    "removable_media_devices": "removableMedia",
    "apple_devices": "appleDevice",
    "portable_devices": "portableDevice",
    "bluetooth_devices": "bluetoothDevice",
}
GENERIC_ACCESS = ["generic_read", "generic_write", "generic_execute"]


def guid() -> str:
    return str(uuid.uuid4())


# --- low-level builders ----------------------------------------------------


def make_group(name: str, clauses: list[dict], op: str = "all") -> dict:
    return {
        "$type": "device",
        "id": guid(),
        "name": name,
        "query": {"$type": op, "clauses": clauses},
    }


def make_entry(
    access: list[str], enforcement: str, *, etype: str = "generic", options: list[str] | None = None
) -> dict:
    enf: dict[str, Any] = {"$type": enforcement}
    if options:
        enf["options"] = options
    return {"$type": etype, "id": guid(), "enforcement": enf, "access": access}


def make_rule(
    name: str, *, include: list[str], exclude: list[str] | None = None, entries: list[dict]
) -> dict:
    rule = {"id": guid(), "name": name, "includeGroups": include, "entries": entries}
    if exclude:
        rule["excludeGroups"] = exclude
    return rule


def assemble(
    *,
    features: dict[str, bool],
    default_enforcement: str,
    groups: list[dict],
    rules: list[dict],
    ux_target: str | None = None,
) -> dict:
    settings: dict[str, Any] = {
        "features": {fam: {"disable": disabled} for fam, disabled in features.items()},
        "global": {"defaultEnforcement": default_enforcement},
    }
    if ux_target:
        settings["ux"] = {"navigationTarget": ux_target}
    return {"settings": settings, "groups": groups, "rules": rules}


# --- canned scenarios ------------------------------------------------------


def scenario_block_removable(read_only: bool = False, audit: bool = False) -> dict:
    grp = make_group(
        "All removable media",
        [{"$type": "primaryId", "value": "removable_media_devices"}],
    )
    if audit:
        access, enf, opts = GENERIC_ACCESS, "auditDeny", ["send_event", "show_notification"]
    elif read_only:
        access, enf, opts = ["generic_write", "generic_execute"], "deny", None
    else:
        access, enf, opts = GENERIC_ACCESS, "deny", None
    rule = make_rule(
        "Read-only removable media"
        if read_only
        else "Audit removable media"
        if audit
        else "Block removable media",
        include=[grp["id"]],
        entries=[make_entry(access, enf, options=opts)],
    )
    return assemble(
        features={"removableMedia": False},
        default_enforcement="allow",
        groups=[grp],
        rules=[rule],
    )


def scenario_allow_only_approved(vendor_id: str = "", serial: str = "") -> dict:
    all_rm = make_group(
        "All removable media",
        [{"$type": "primaryId", "value": "removable_media_devices"}],
    )
    clauses = []
    if vendor_id:
        clauses.append({"$type": "vendorId", "value": vendor_id})
    if serial:
        clauses.append({"$type": "serialNumber", "value": serial})
    if not clauses:  # fall back to an apfs-encrypted exception if nothing given
        clauses.append({"$type": "encryption", "value": "apfs"})
    approved = make_group("Approved removable media", clauses, op="all")
    rule = make_rule(
        "Block removable media except approved",
        include=[all_rm["id"]],
        exclude=[approved["id"]],
        entries=[make_entry(GENERIC_ACCESS, "deny")],
    )
    return assemble(
        features={"removableMedia": False},
        default_enforcement="allow",
        groups=[all_rm, approved],
        rules=[rule],
    )


def scenario_block_family(primary: str) -> dict:
    grp = make_group(
        PRIMARY_IDS[primary],
        [{"$type": "primaryId", "value": primary}],
    )
    rule = make_rule(
        f"Block {PRIMARY_IDS[primary]}",
        include=[grp["id"]],
        entries=[make_entry(GENERIC_ACCESS, "deny")],
    )
    return assemble(
        features={FEATURE_FOR_PRIMARY[primary]: False},
        default_enforcement="allow",
        groups=[grp],
        rules=[rule],
    )


# --- interactive entry point ----------------------------------------------


def interactive_device_control(preset: dict | None = None) -> dict | None:
    """Return a device control policy dict, or None to skip."""
    if not prompts.confirm(
        "Configure Device Control (USB / removable media)?", default=bool(preset)
    ):
        return None

    if preset and not prompts.confirm(
        "Rebuild Device Control? (No keeps the existing policy)", default=False
    ):
        return preset

    mode = prompts.select(
        "How do you want to define the Device Control policy?",
        [
            "Guided scenario (recommended)",
            "Import an existing policy JSON file",
            "Skip",
        ],
    )

    if mode.startswith("Import"):
        path = Path(prompts.text("Path to device control policy JSON"))
        if not path.exists():
            print(f"  (not found: {path} - skipping Device Control)")
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"  Invalid JSON: {exc} - skipping Device Control")
            return None

    if mode.startswith("Skip"):
        return None

    scenario = prompts.select(
        "Choose a scenario:",
        [
            "Block ALL removable media (full block)",
            "Removable media READ-ONLY (block write/execute)",
            "Allow ONLY an approved USB (block the rest)",
            "AUDIT removable media (log only, no blocking)",
            "Block Apple devices (iPhone/iPad)",
            "Block portable devices (cameras/PTP)",
        ],
    )
    ux = prompts.text("Notification help URL (optional)", default="")

    if scenario.startswith("Block ALL"):
        policy = scenario_block_removable()
    elif scenario.startswith("Removable media READ-ONLY"):
        policy = scenario_block_removable(read_only=True)
    elif scenario.startswith("Allow ONLY"):
        vid = prompts.text("Approved vendor ID (4-digit hex, optional)", default="")
        ser = prompts.text("Approved serial number (optional)", default="")
        policy = scenario_allow_only_approved(vendor_id=vid.strip(), serial=ser.strip())
    elif scenario.startswith("AUDIT"):
        policy = scenario_block_removable(audit=True)
    elif scenario.startswith("Block Apple"):
        policy = scenario_block_family("apple_devices")
    else:
        policy = scenario_block_family("portable_devices")

    if ux.strip():
        policy["settings"].setdefault("ux", {})["navigationTarget"] = ux.strip()
    return policy


def wire_into_settings(settings: dict, policy: dict) -> None:
    """
    Attach a device control policy to a (nested) wdav settings dict in place:
      - deviceControl.policy = <policy>
      - dlp.features gets a DC_in_dlp / enabled entry (idempotent)
    """
    settings.setdefault("deviceControl", {})["policy"] = policy
    dlp = settings.setdefault("dlp", {})
    features = dlp.setdefault("features", [])
    if not any(f.get("name") == "DC_in_dlp" for f in features):
        features.append({"name": "DC_in_dlp", "state": "enabled"})
