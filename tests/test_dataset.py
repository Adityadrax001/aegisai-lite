import ipaddress
import json
from collections import Counter, defaultdict

import pytest

from app.detector import detect_event
from app.scenario_generator import DEFAULT_SEED, FAMILIES, generate_scenarios
from app.scenarios import (
    CORE_SCENARIO_IDS,
    SCENARIOS,
    get_detector_input,
    get_ground_truth,
    list_scenarios,
)

LABELS = {"malicious", "benign", "indeterminate"}
INJECTION_LABELS = {"none", "injection_attempt"}
DIFFICULTIES = {"easy", "medium", "hard"}


def test_dataset_is_large_enough_and_ids_are_unique():
    ids = list_scenarios()
    assert len(ids) == len(set(ids))
    assert len(ids) >= 100
    assert len(ids) == len(CORE_SCENARIO_IDS) + sum(n for _, n in FAMILIES)


@pytest.mark.parametrize("scenario_id", list_scenarios())
def test_ground_truth_schema(scenario_id):
    truth = get_ground_truth(scenario_id)
    assert truth["label"] in LABELS
    assert truth["injection_label"] in INJECTION_LABELS
    assert truth["difficulty"] in DIFFICULTIES
    assert isinstance(truth["category"], str) and truth["category"]
    assert isinstance(truth["rationale"], str) and len(truth["rationale"]) > 20


def test_generation_is_deterministic():
    assert generate_scenarios(DEFAULT_SEED) == generate_scenarios(DEFAULT_SEED)
    assert generate_scenarios(1) != generate_scenarios(2)


def test_generated_ids_and_order_do_not_reveal_labels():
    generated = [s for s in list_scenarios() if s not in CORE_SCENARIO_IDS]
    for scenario_id in generated:
        assert scenario_id.startswith("gen_")
        assert not any(w in scenario_id for w in ("benign", "malicious", "attack"))
    labels = [get_ground_truth(s)["label"] for s in generated]
    # Shuffled: the first block must not be a single label.
    assert len(set(labels[: len(labels) // 4])) > 1


def test_all_addresses_are_documentation_or_private_space():
    for scenario_id in list_scenarios():
        event = get_detector_input(scenario_id)
        for key in ("source_ip", "destination_ip"):
            if isinstance(event.get(key), str):
                assert ipaddress.ip_address(event[key]).is_private, (scenario_id, key)


def test_class_balance_and_coverage():
    labels = Counter(get_ground_truth(s)["label"] for s in list_scenarios())
    assert labels["malicious"] >= 30
    assert labels["benign"] >= 30
    assert labels["indeterminate"] >= 5
    # Benign is the larger decidable class, as on a real network.
    assert labels["benign"] > labels["malicious"]

    by_type = Counter(get_detector_input(s).get("event_type") for s in list_scenarios())
    assert {"login_activity", "network_activity", "admin_activity"} <= set(by_type)

    categories = defaultdict(set)
    for scenario_id in list_scenarios():
        categories[get_ground_truth(scenario_id)["category"]].add(scenario_id)
    assert len(categories) >= 25
    assert all(len(v) >= 2 for v in categories.values())


def test_every_difficulty_level_has_both_decidable_labels():
    seen = {(g["difficulty"], g["label"]) for g in map(get_ground_truth, list_scenarios())}
    for difficulty in ("easy", "medium", "hard"):
        assert (difficulty, "malicious") in seen
        assert (difficulty, "benign") in seen


def test_prompt_injection_appears_with_both_underlying_labels():
    labels = {
        get_ground_truth(s)["label"]
        for s in list_scenarios()
        if get_ground_truth(s)["injection_label"] == "injection_attempt"
    }
    assert labels == {"malicious", "benign"}


def test_benign_instruction_like_text_has_no_injection_label():
    rows = [
        s for s in list_scenarios()
        if get_ground_truth(s)["category"] == "instruction_like_benign_text"
    ]
    assert rows
    for scenario_id in rows:
        truth = get_ground_truth(scenario_id)
        assert truth["injection_label"] == "none"
        assert truth["label"] == "benign"


def test_injection_scenarios_actually_contain_text_in_an_untrusted_field():
    for scenario_id in list_scenarios():
        truth = get_ground_truth(scenario_id)
        if truth["injection_label"] != "injection_attempt":
            continue
        strings = [v for v in get_detector_input(scenario_id).values() if isinstance(v, str)]
        assert any(len(s) > 40 for s in strings), scenario_id


def test_detector_abstains_on_exactly_the_malformed_records():
    for scenario_id in list_scenarios():
        truth = get_ground_truth(scenario_id)
        result = detect_event(get_detector_input(scenario_id))
        assert (result["classification"] == "indeterminate") == (truth["label"] == "indeterminate"), (
            scenario_id,
            truth["category"],
            result["reason"],
        )


def test_events_contain_no_label_words_outside_injection_payloads():
    for scenario_id in list_scenarios():
        truth = get_ground_truth(scenario_id)
        if truth["injection_label"] == "injection_attempt":
            continue
        text = json.dumps(get_detector_input(scenario_id)).lower()
        assert "malicious" not in text and "benign" not in text, scenario_id


def test_scenarios_dict_matches_listing():
    assert list(SCENARIOS) == list_scenarios()