"""
Turns a settings dict (nested, matching the com.microsoft.wdav schema) into
deployable artefacts using only the standard library (plistlib), so it runs on
Windows and macOS identically.

Outputs, per the two ways admins actually consume these:
  * <name>.mobileconfig  - full configuration profile (Intune custom / Jamf
                           custom profile / any MDM that ingests .mobileconfig)
  * com.microsoft.wdav.plist - the inner settings dict only, for Jamf Pro's
                           "Application & Custom Settings > Upload PLIST File"
                           against the com.microsoft.wdav preference domain.
"""

from __future__ import annotations

import json
import plistlib
import uuid
from pathlib import Path
from typing import Any


def _new_uuid() -> str:
    return str(uuid.uuid4()).upper()


def set_nested(root: dict[str, Any], path: list[str], value: Any) -> None:
    """Set value at a dotted path, creating intermediate dicts."""
    node = root
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value


def build_wdav_payload(
    settings: dict[str, Any],
    organisation: str,
    identifier: str,
    *,
    payload_type: str = "com.microsoft.wdav",
    display_name: str = "Microsoft Defender for Endpoint settings",
) -> dict[str, Any]:
    """One com.microsoft.wdav[.ext] payload dict carrying the settings inline."""
    payload: dict[str, Any] = {
        "PayloadType": payload_type,
        "PayloadVersion": 1,
        "PayloadIdentifier": identifier,
        "PayloadUUID": _new_uuid(),
        "PayloadEnabled": True,
        "PayloadDisplayName": display_name,
        "PayloadOrganization": organisation,
    }
    payload.update(settings)
    return payload


def wrap_profile(
    payloads: list[dict[str, Any]],
    *,
    display_name: str,
    description: str,
    identifier: str,
    organisation: str,
    removal_disallowed: bool = True,
) -> dict[str, Any]:
    """Wrap one or more payloads in a top-level Configuration profile."""
    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadScope": "System",
        "PayloadUUID": _new_uuid(),
        "PayloadIdentifier": identifier,
        "PayloadDisplayName": display_name,
        "PayloadDescription": description,
        "PayloadOrganization": organisation,
        "PayloadRemovalDisallowed": removal_disallowed,
        "PayloadEnabled": True,
        "PayloadContent": payloads,
    }


def write_plist(obj: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        plistlib.dump(obj, fh, sort_keys=False)


def write_settings_profile(
    settings: dict[str, Any],
    out_dir: Path,
    *,
    filename: str,
    payload_type: str,
    display_name: str,
    description: str,
    organisation: str,
    identifier: str,
) -> Path:
    """Write a single wdav-style configuration profile."""
    payload = build_wdav_payload(
        settings, organisation, identifier, payload_type=payload_type, display_name=display_name
    )
    profile = wrap_profile(
        [payload],
        display_name=display_name,
        description=description,
        identifier=f"{identifier}.profile",
        organisation=organisation,
    )
    out = out_dir / filename
    write_plist(profile, out)
    return out


# Defender behavioural sections that, together with deviceControl, are best
# kept in the secondary com.microsoft.wdav.ext profile when splitting.
EXT_SECTIONS = ("deviceControl", "dlp")


def split_settings(settings: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Partition nested settings into (main wdav, ext wdav) for the 'concern' split.

    Device Control and its dlp feature flag move to the .ext domain so the bulky
    policy lives in its own profile. macOS only allows ONE profile per identifier,
    so this two-identifier split is the maximum safe fragmentation of wdav.
    """
    main = {k: v for k, v in settings.items() if k not in EXT_SECTIONS}
    ext = {k: v for k, v in settings.items() if k in EXT_SECTIONS}
    return main, ext


def emit(
    settings: dict[str, Any],
    out_dir: Path,
    *,
    organisation: str,
    identifier_prefix: str,
    strategy: str = "concern",
    supporting_payloads: list[dict[str, Any]] | None = None,
    device_control_policy: dict[str, Any] | None = None,
) -> list[Path]:
    """
    Emit profiles according to the chosen split strategy.

    strategy="concern" (default): one profile per Apple payload domain; Defender
        behavioural settings in com.microsoft.wdav, with Device Control + dlp
        split into a com.microsoft.wdav.ext profile. Recommended.
    strategy="single": every payload (wdav + all supporting) in ONE .mobileconfig.
        Valid, but harder to scope/troubleshoot - offered for completeness.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    supporting_payloads = supporting_payloads or []
    written: list[Path] = []

    if strategy == "single":
        payloads: list[dict[str, Any]] = []
        if settings:
            payloads.append(build_wdav_payload(settings, organisation, f"{identifier_prefix}.wdav"))
        payloads.extend(supporting_payloads)
        profile = wrap_profile(
            payloads,
            display_name="Microsoft Defender for Endpoint (combined)",
            description="All Defender and supporting payloads in a single profile.",
            identifier=f"{identifier_prefix}.combined",
            organisation=organisation,
        )
        out = out_dir / "MDE-combined.mobileconfig"
        write_plist(profile, out)
        return [out]

    # --- concern split -----------------------------------------------------
    main, ext = split_settings(settings)

    if main:
        written.append(
            write_settings_profile(
                main,
                out_dir,
                filename="MDE-01-defender-settings.mobileconfig",
                payload_type="com.microsoft.wdav",
                display_name="MDE - Defender Settings",
                description="Antivirus, cloud, EDR, tamper and network protection preferences.",
                organisation=organisation,
                identifier=f"{identifier_prefix}.wdav",
            )
        )
        # Inner plist for Jamf 'Upload PLIST File' against com.microsoft.wdav
        write_plist(main, out_dir / "com.microsoft.wdav.plist")
        written.append(out_dir / "com.microsoft.wdav.plist")

    if ext:
        written.append(
            write_settings_profile(
                ext,
                out_dir,
                filename="MDE-02-device-control.mobileconfig",
                payload_type="com.microsoft.wdav.ext",
                display_name="MDE - Device Control",
                description="Device Control policy and DLP feature flag (com.microsoft.wdav.ext).",
                organisation=organisation,
                identifier=f"{identifier_prefix}.wdav.ext",
            )
        )
        write_plist(ext, out_dir / "com.microsoft.wdav.ext.plist")
        written.append(out_dir / "com.microsoft.wdav.ext.plist")

    # Raw Device Control policy JSON, for `mdatp device-control policy validate`
    if device_control_policy is not None:
        dc_path = out_dir / "device_control_policy.json"
        dc_path.write_text(json.dumps(device_control_policy, indent=2), encoding="utf-8")
        written.append(dc_path)

    return written
