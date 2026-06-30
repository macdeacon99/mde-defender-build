"""Tests for Device Control policy builders and wiring."""

from mdebuilder import devicecontrol as dc


def _all_guids(policy):
    ids = [g["id"] for g in policy["groups"]]
    for rule in policy["rules"]:
        ids.append(rule["id"])
        ids.extend(e["id"] for e in rule["entries"])
    return ids


def test_block_removable_structure():
    policy = dc.scenario_block_removable()
    assert set(policy) == {"settings", "groups", "rules"}
    assert policy["settings"]["features"]["removableMedia"]["disable"] is False
    assert policy["rules"][0]["entries"][0]["enforcement"]["$type"] == "deny"
    assert policy["rules"][0]["entries"][0]["access"] == dc.GENERIC_ACCESS


def test_read_only_blocks_write_execute_only():
    policy = dc.scenario_block_removable(read_only=True)
    access = policy["rules"][0]["entries"][0]["access"]
    assert "generic_read" not in access
    assert "generic_write" in access and "generic_execute" in access


def test_audit_uses_auditdeny():
    policy = dc.scenario_block_removable(audit=True)
    enf = policy["rules"][0]["entries"][0]["enforcement"]
    assert enf["$type"] == "auditDeny"
    assert "send_event" in enf["options"]


def test_allow_only_approved_has_include_and_exclude():
    policy = dc.scenario_allow_only_approved(vendor_id="0951")
    assert len(policy["groups"]) == 2
    rule = policy["rules"][0]
    assert "includeGroups" in rule and "excludeGroups" in rule
    # the excluded group must reference an existing group id
    group_ids = {g["id"] for g in policy["groups"]}
    assert set(rule["excludeGroups"]).issubset(group_ids)


def test_guids_are_unique_and_valid():
    policy = dc.scenario_allow_only_approved(vendor_id="0951", serial="ABC123")
    ids = _all_guids(policy)
    assert len(ids) == len(set(ids))  # unique
    for i in ids:
        assert len(i) == 36 and i.count("-") == 4  # uuid4 shape


def test_block_family():
    policy = dc.scenario_block_family("apple_devices")
    clause = policy["groups"][0]["query"]["clauses"][0]
    assert clause == {"$type": "primaryId", "value": "apple_devices"}
    assert policy["settings"]["features"]["appleDevice"]["disable"] is False


def test_wire_into_settings_is_idempotent():
    settings: dict = {"antivirusEngine": {"enableRealTimeProtection": True}}
    policy = dc.scenario_block_removable()
    dc.wire_into_settings(settings, policy)
    dc.wire_into_settings(settings, policy)  # twice
    assert settings["deviceControl"]["policy"] is policy
    flags = [f for f in settings["dlp"]["features"] if f["name"] == "DC_in_dlp"]
    assert len(flags) == 1  # not duplicated
    assert flags[0]["state"] == "enabled"
