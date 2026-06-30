"""Tests for the Microsoft schema loader and walker."""

from mdebuilder.schema import ArraySetting, Setting, node_kind


def test_schema_version_and_sections(model):
    assert model.version  # non-empty
    # The 10 documented sections must all be present.
    for section in (
        "antivirusEngine",
        "cloudService",
        "userInterface",
        "edr",
        "features",
        "tamperProtection",
        "deviceControl",
        "networkProtection",
        "dlp",
        "scheduledScan",
    ):
        assert section in model.sections


def test_node_kind_classification():
    assert node_kind({"type": "boolean"}) == "boolean"
    assert node_kind({"type": "string", "enum": ["a", "b"]}) == "string"
    assert node_kind({"type": "array", "items": {"type": "string"}}) == "array"
    assert node_kind({"properties": {"x": {"type": "boolean"}}}) == "object"


def test_known_scalar_setting(model):
    settings = {s.dotted: s for s in model.settings_for("antivirusEngine")}
    rtp = settings["antivirusEngine.enableRealTimeProtection"]
    assert isinstance(rtp, Setting)
    assert rtp.kind == "boolean"
    assert rtp.default is True
    assert rtp.section == "antivirusEngine"


def test_enum_setting_has_choices(model):
    settings = {s.dotted: s for s in model.settings_for("tamperProtection")}
    enf = settings["tamperProtection.enforcementLevel"]
    assert isinstance(enf, Setting)
    assert enf.enum == ["disabled", "audit", "block"]


def test_array_setting_detected(model):
    settings = {s.dotted: s for s in model.settings_for("antivirusEngine")}
    exclusions = settings["antivirusEngine.exclusions"]
    assert isinstance(exclusions, ArraySetting)
    assert exclusions.item_kind == "object"
    assert "$type" in exclusions.item_properties


def test_every_section_walks_without_error(model):
    for section in model.sections:
        result = model.settings_for(section)
        assert isinstance(result, list)
