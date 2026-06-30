"""Tests for baseline save/load and dotted-path expansion."""

import yaml

from mdebuilder.baselines import baseline_to_settings, load_baseline, save_baseline


def test_baseline_to_settings_expands_dotted_paths():
    flat = {
        "antivirusEngine.enableRealTimeProtection": True,
        "antivirusEngine.scanArchives": True,
        "cloudService.enabled": True,
    }
    nested = baseline_to_settings(flat)
    assert nested["antivirusEngine"]["enableRealTimeProtection"] is True
    assert nested["antivirusEngine"]["scanArchives"] is True
    assert nested["cloudService"]["enabled"] is True


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "baseline.yaml"
    meta = {"name": "T", "organisation": "Org", "identifier_prefix": "com.test.mde"}
    save_baseline(
        path,
        meta=meta,
        wdav={"tamperProtection.enforcementLevel": "block"},
        supporting=["system_extensions", "full_disk_access"],
        device_control={"settings": {}, "groups": [], "rules": []},
        strategy="concern",
    )
    doc = load_baseline(path)
    assert doc["metadata"]["split_strategy"] == "concern"
    assert doc["wdav_settings"]["tamperProtection.enforcementLevel"] == "block"
    assert "system_extensions" in doc["supporting_profiles"]
    assert doc["device_control"] == {"settings": {}, "groups": [], "rules": []}


def test_wdav_settings_are_sorted_for_clean_diffs(tmp_path):
    path = tmp_path / "baseline.yaml"
    save_baseline(
        path,
        meta={"organisation": "Org", "identifier_prefix": "com.test.mde"},
        wdav={"cloudService.enabled": True, "antivirusEngine.scanArchives": True},
        supporting=[],
    )
    raw = yaml.safe_load(path.read_text())
    keys = list(raw["wdav_settings"].keys())
    assert keys == sorted(keys)
