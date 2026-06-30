"""Tests for profile assembly, the wdav/.ext split, and emit strategies."""

import plistlib

from mdebuilder.profile import (
    build_wdav_payload,
    emit,
    set_nested,
    split_settings,
)


def test_set_nested_creates_path():
    root: dict = {}
    set_nested(root, ["antivirusEngine", "enableRealTimeProtection"], True)
    assert root == {"antivirusEngine": {"enableRealTimeProtection": True}}


def test_build_payload_respects_payload_type():
    p = build_wdav_payload(
        {"x": 1}, "Org", "com.test.wdav.ext", payload_type="com.microsoft.wdav.ext"
    )
    assert p["PayloadType"] == "com.microsoft.wdav.ext"
    assert p["x"] == 1


def test_split_moves_device_control_and_dlp_to_ext():
    settings = {
        "antivirusEngine": {"enableRealTimeProtection": True},
        "deviceControl": {"policy": {"settings": {}}},
        "dlp": {"features": [{"name": "DC_in_dlp", "state": "enabled"}]},
    }
    main, ext = split_settings(settings)
    assert "antivirusEngine" in main
    assert "deviceControl" not in main and "dlp" not in main
    assert set(ext) == {"deviceControl", "dlp"}


def test_emit_concern_produces_main_and_ext(tmp_path):
    settings = {
        "antivirusEngine": {"enableRealTimeProtection": True},
        "deviceControl": {"policy": {"settings": {}, "groups": [], "rules": []}},
        "dlp": {"features": [{"name": "DC_in_dlp", "state": "enabled"}]},
    }
    written = emit(
        settings,
        tmp_path,
        organisation="Org",
        identifier_prefix="com.test.mde",
        strategy="concern",
        device_control_policy=settings["deviceControl"]["policy"],
    )
    names = {p.name for p in written}
    assert "MDE-01-defender-settings.mobileconfig" in names
    assert "MDE-02-device-control.mobileconfig" in names
    assert "device_control_policy.json" in names

    main = plistlib.load((tmp_path / "MDE-01-defender-settings.mobileconfig").open("rb"))
    main_payload = main["PayloadContent"][0]
    assert main_payload["PayloadType"] == "com.microsoft.wdav"
    assert "deviceControl" not in main_payload  # isolated in .ext

    ext = plistlib.load((tmp_path / "MDE-02-device-control.mobileconfig").open("rb"))
    ext_payload = ext["PayloadContent"][0]
    assert ext_payload["PayloadType"] == "com.microsoft.wdav.ext"
    assert "deviceControl" in ext_payload


def test_emit_concern_without_device_control_has_no_ext(tmp_path):
    settings = {"antivirusEngine": {"enableRealTimeProtection": True}}
    written = emit(
        settings, tmp_path, organisation="Org", identifier_prefix="com.test.mde", strategy="concern"
    )
    names = {p.name for p in written}
    assert "MDE-01-defender-settings.mobileconfig" in names
    assert "MDE-02-device-control.mobileconfig" not in names


def test_emit_single_is_one_profile_with_all_payloads(tmp_path):
    settings = {"antivirusEngine": {"enableRealTimeProtection": True}}
    supporting = [{"PayloadType": "com.apple.system-extension-policy"}]
    written = emit(
        settings,
        tmp_path,
        organisation="Org",
        identifier_prefix="com.test.mde",
        strategy="single",
        supporting_payloads=supporting,
    )
    assert len(written) == 1
    prof = plistlib.load(written[0].open("rb"))
    types = [p["PayloadType"] for p in prof["PayloadContent"]]
    assert "com.microsoft.wdav" in types
    assert "com.apple.system-extension-policy" in types


def test_generated_profiles_are_valid_plists(tmp_path):
    settings = {"cloudService": {"enabled": True}}
    written = emit(
        settings, tmp_path, organisation="Org", identifier_prefix="com.test.mde", strategy="concern"
    )
    for p in written:
        if p.suffix in (".mobileconfig", ".plist"):
            with p.open("rb") as fh:
                plistlib.load(fh)  # raises on malformed
