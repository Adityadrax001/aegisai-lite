import json

import pytest

from app.scenarios import (
    CORE_SCENARIO_IDS,
    SCENARIOS,
    get_detector_input,
    get_ground_truth,
    list_scenarios,
    run_scenario,
)

EXPECTED = {
    "brute_force": ("malicious", "none"),
    "normal_login": ("benign", "none"),
    "suspicious_outbound": ("malicious", "none"),
    "benign_admin": ("benign", "none"),
    "benign_backup": ("benign", "none"),
    "prompt_injection": ("benign", "injection_attempt"),
}

FORBIDDEN_KEYS = {
    "ground_truth",
    "label",
    "injection_label",
    "rationale",
    "category",
    "difficulty",
    "scenario_id",
    "expected_label",
}
LABEL_VALUES = {"malicious", "benign", "indeterminate", "injection_attempt", "none"}


def _all_keys(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key
            yield from _all_keys(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _all_keys(item)


def _all_values(obj):
    if isinstance(obj, dict):
        for value in obj.values():
            yield from _all_values(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _all_values(item)
    else:
        yield obj


def test_six_core_scenarios_are_present():
    assert set(CORE_SCENARIO_IDS) == set(EXPECTED)
    assert len(CORE_SCENARIO_IDS) == 6
    assert set(CORE_SCENARIO_IDS) <= set(list_scenarios())


@pytest.mark.parametrize("scenario_id", EXPECTED)
def test_core_scenario_has_expected_ground_truth(scenario_id):
    event = get_detector_input(scenario_id)
    truth = get_ground_truth(scenario_id)
    label, injection_label = EXPECTED[scenario_id]

    assert event["simulated"] is True
    assert "event_type" in event
    assert truth["label"] == label
    assert truth["injection_label"] == injection_label
    assert isinstance(truth["rationale"], str) and truth["rationale"].strip()


@pytest.mark.parametrize("scenario_id", list_scenarios())
def test_detector_input_does_not_expose_ground_truth(scenario_id):
    event = get_detector_input(scenario_id)
    truth = get_ground_truth(scenario_id)

    assert not FORBIDDEN_KEYS & set(_all_keys(event))
    assert not LABEL_VALUES & {v for v in _all_values(event) if isinstance(v, str)}

    serialized = json.dumps(event).lower()
    assert scenario_id.lower() not in serialized
    assert truth["rationale"].lower() not in serialized
    assert truth["category"].lower() not in serialized


def test_run_scenario_still_includes_scenario_id():
    # Existing behaviour, kept for callers that rely on it. It leaks the
    # label for named core scenarios, which is why systems should be fed
    # get_detector_input() instead.
    assert run_scenario("benign_admin")["scenario_id"] == "benign_admin"
    assert "scenario_id" not in get_detector_input("benign_admin")


@pytest.mark.parametrize("scenario_id", CORE_SCENARIO_IDS)
def test_returned_data_is_a_copy(scenario_id):
    event = get_detector_input(scenario_id)
    event["tampered"] = True
    assert "tampered" not in get_detector_input(scenario_id)

    truth = get_ground_truth(scenario_id)
    truth["label"] = "tampered"
    assert get_ground_truth(scenario_id)["label"] != "tampered"


def test_unknown_scenario_raises():
    for fn in (run_scenario, get_detector_input, get_ground_truth):
        with pytest.raises(ValueError):
            fn("nope")


def test_hostile_text_only_in_injection_core_scenario():
    hostile = "ignore all previous instructions"
    for scenario_id in CORE_SCENARIO_IDS:
        text = json.dumps(get_detector_input(scenario_id)).lower()
        assert (hostile in text) == (scenario_id == "prompt_injection")