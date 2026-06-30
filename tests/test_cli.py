"""End-to-end CLI tests driving main() with non-interactive arguments."""

from pathlib import Path

import pytest

from mdebuilder.cli import main

EXAMPLE_DC = Path("examples/baselines/example_devicecontrol.yaml")
EXAMPLE_BASIC = Path("examples/baselines/example_recommended.yaml")


def test_list_runs(capsys):
    assert main(["--list"]) == 0
    out = capsys.readouterr().out
    assert "antivirusEngine" in out
    assert "Supporting profiles:" in out


def test_build_from_basic_baseline_concern(tmp_path):
    rc = main(["--from-baseline", str(EXAMPLE_BASIC), "--out", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "MDE-01-defender-settings.mobileconfig").exists()
    assert (tmp_path / "com.microsoft.wdav.plist").exists()
    # no device control in the basic baseline
    assert not (tmp_path / "MDE-02-device-control.mobileconfig").exists()


@pytest.mark.skipif(not EXAMPLE_DC.exists(), reason="device control example missing")
def test_build_from_devicecontrol_baseline(tmp_path):
    rc = main(["--from-baseline", str(EXAMPLE_DC), "--out", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "MDE-02-device-control.mobileconfig").exists()
    assert (tmp_path / "device_control_policy.json").exists()


def test_build_single_strategy_override(tmp_path):
    rc = main(["--from-baseline", str(EXAMPLE_BASIC), "--out", str(tmp_path), "--split", "single"])
    assert rc == 0
    assert (tmp_path / "MDE-combined.mobileconfig").exists()


def test_validate_after_build(tmp_path, capsys):
    main(["--from-baseline", str(EXAMPLE_BASIC), "--out", str(tmp_path)])
    rc = main(["--validate", "--out", str(tmp_path)])
    assert rc == 0
    assert "OK" in capsys.readouterr().out
