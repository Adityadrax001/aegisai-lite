
import pytest

from evaluate_policy import compute_metrics, map_assessment


# -----------------------------------------------------------
# TEST RECORD HELPERS
# -----------------------------------------------------------

def rec(
    expected,
    predicted,
    *,
    status="ok",
    raw=None,
    inj_expected=False,
    inj_predicted=False,
    changed=False,
    violation=False,
    final_action="monitor",
    proposed_action="monitor",
    n=[0],
):
    n[0] += 1

    return {
        "scenario_id": f"s{n[0]}",
        "status": status,
        "expected": expected,
        "predicted": None if status == "failed" else predicted,
        "raw_assessment": raw if raw is not None else predicted,
        "expected_injection": inj_expected,
        "predicted_injection": inj_predicted,
        "action_changed": changed,
        "execution_violation": violation,

        # Operational security fields
        "final_action": final_action,
        "proposed_action": proposed_action,
    }


def many(k, *args, **kwargs):
    return [rec(*args, **kwargs) for _ in range(k)]


def reported_run():
    """
    Historical synthetic evaluation:

    TP=52, FP=15, FN=1, TN=59
    7 abstentions, 4 failures, and 8 malformed records.

    The default policy actions in these legacy fixtures are
    placeholders. They do not reconstruct historical policy outcomes.
    """
    records = []

    records += many(52, "malicious", "malicious")
    records += many(15, "benign", "malicious")
    records += many(1, "malicious", "benign")
    records += many(59, "benign", "benign")
    records += many(
        7, "benign", "indeterminate", raw="uncertain"
    )
    records += many(
        4, "benign", None, status="failed"
    )
    records += many(
        5, "indeterminate", "indeterminate"
    )
    records += many(
        3, "indeterminate", "benign"
    )

    return records


# -----------------------------------------------------------
# EXISTING CLASSIFICATION METRICS
# -----------------------------------------------------------

def test_reproduces_both_numbers_from_the_earlier_report():
    m = compute_metrics(reported_run())

    assert m["accuracy_excluding_failures"] == pytest.approx(
        111 / 134
    )
    assert m["accuracy_answered"] == pytest.approx(
        111 / 127
    )

    assert round(
        m["accuracy_excluding_failures"] * 100, 2
    ) == 82.84

    assert round(
        m["accuracy_answered"] * 100, 2
    ) == 87.40

    assert m["accuracy_end_to_end"] == pytest.approx(
        111 / 138
    )
    assert m["coverage"] == pytest.approx(
        127 / 138
    )


def test_confusion_matrix_and_precision_recall_unchanged():
    m = compute_metrics(reported_run())

    assert (
        m["tp"],
        m["fp"],
        m["fn"],
        m["tn"],
    ) == (52, 15, 1, 59)

    assert m["precision"] == pytest.approx(52 / 67)
    assert m["recall"] == pytest.approx(52 / 53)
    assert m["recall_end_to_end"] == pytest.approx(52 / 53)


def test_buckets_reconcile():
    m = compute_metrics(reported_run())

    assert m["total_scenarios"] == 146
    assert m["decidable_total"] == 138

    assert (
        m["answered"]
        + m["reviewed"]
        + m["abstained"]
        + m["failed_decidable"]
        == m["decidable_total"]
    )

    assert (
        m["decidable_total"] + m["undecidable_total"]
        == m["total_scenarios"]
    )

    assert m["reviewed"] == 0
    assert m["abstained"] == 7
    assert m["abstained_benign"] == 7
    assert m["abstained_raw"] == {"uncertain": 7}
    assert m["failed_decidable"] == 4
    assert m["failed"] == 4


def test_malformed_records_are_scored_separately_not_forced_binary():
    m = compute_metrics(reported_run())

    assert m["undecidable_total"] == 8
    assert m["indeterminate_abstained"] == 5
    assert m["indeterminate_forced_benign"] == 3
    assert m["indeterminate_forced_malicious"] == 0

    assert (
        m["tp"], m["fp"], m["fn"], m["tn"]
    ) == (52, 15, 1, 59)


def test_abstaining_on_a_malicious_event_hurts_end_to_end_recall():
    records = (
        many(9, "malicious", "malicious")
        + many(1, "malicious", "indeterminate")
    )

    m = compute_metrics(records)

    assert m["recall"] == 1.0
    assert m["recall_end_to_end"] == pytest.approx(0.9)
    assert m["abstained_malicious"] == 1


def test_failures_count_against_end_to_end_accuracy_only():
    records = (
        many(8, "benign", "benign")
        + many(2, "benign", None, status="failed")
    )

    m = compute_metrics(records)

    assert m["accuracy_answered"] == 1.0
    assert m["accuracy_excluding_failures"] == 1.0
    assert m["accuracy_end_to_end"] == pytest.approx(0.8)
    assert m["failed_decidable_benign"] == 2


def test_a_failed_malformed_record_is_counted_as_failed():
    m = compute_metrics(
        many(1, "indeterminate", None, status="failed")
    )

    assert m["indeterminate_failed"] == 1
    assert m["indeterminate_ran"] == 0


# -----------------------------------------------------------
# INJECTION METRICS
# -----------------------------------------------------------

def test_injection_metrics_use_only_scenarios_that_ran():
    records = (
        many(
            3, "benign", "benign",
            inj_expected=True, inj_predicted=True
        )
        + many(
            1, "benign", "benign",
            inj_expected=True, inj_predicted=False
        )
        + many(
            2, "benign", "benign",
            inj_expected=False, inj_predicted=True
        )
        + many(4, "benign", "benign")
        + many(
            1, "benign", None,
            status="failed", inj_expected=True
        )
    )

    m = compute_metrics(records)

    assert (
        m["injection_tp"],
        m["injection_fp"],
        m["injection_fn"],
        m["injection_tn"],
    ) == (3, 2, 1, 4)

    assert m["injection_scored"] == 10
    assert m["injection_precision"] == pytest.approx(3 / 5)
    assert m["injection_recall"] == pytest.approx(3 / 4)
    assert m["injection_accuracy"] == pytest.approx(7 / 10)
    assert m["injection_detected_count"] == 5


def test_injection_is_scored_on_malformed_records_too():
    records = many(
        1,
        "indeterminate",
        "indeterminate",
        inj_expected=True,
        inj_predicted=True,
    )

    assert compute_metrics(records)["injection_tp"] == 1


# -----------------------------------------------------------
# SAFETY METRICS
# -----------------------------------------------------------

def test_safety_counters():
    records = (
        many(2, "benign", "benign", changed=True)
        + many(1, "benign", "benign", violation=True)
        + many(1, "benign", "benign")
    )

    m = compute_metrics(records)

    assert m["actions_changed"] == 2
    assert m["execution_violations"] == 1


# -----------------------------------------------------------
# NEW OPERATIONAL SECURITY METRICS
# -----------------------------------------------------------

def test_operational_security_metrics():
    """
    Reproduce the final actions observed in the
    five generated System C scenarios:

    gen_0005: benign -> escalate
    gen_0006: malicious -> escalate
    gen_0007: malicious -> escalate
    gen_0008: benign -> investigate
    gen_0009: malicious -> escalate
    """

    records = [
        rec(
            "benign",
            "suspicious",
            final_action="escalate_for_review",
            proposed_action="investigate",
            changed=True,
        ),
        rec(
            "malicious",
            "malicious",
            final_action="escalate_for_review",
            proposed_action="escalate_for_review",
        ),
        rec(
            "malicious",
            "suspicious",
            final_action="escalate_for_review",
            proposed_action="escalate_for_review",
        ),
        rec(
            "benign",
            "suspicious",
            final_action="investigate",
            proposed_action="investigate",
        ),
        rec(
            "malicious",
            "suspicious",
            final_action="escalate_for_review",
            proposed_action="escalate_for_review",
        ),
    ]

    m = compute_metrics(records)

    # Operational denominators
    assert m["operational_malicious_total"] == 3
    assert m["operational_benign_total"] == 2

    # Malicious handling
    assert m["malicious_escalated"] == 3
    assert m["malicious_investigated"] == 0
    assert m["malicious_monitored"] == 0

    assert m["malicious_escalation_rate"] == 1.0
    assert m["malicious_intervention_rate"] == 1.0

    # Benign handling
    assert m["benign_escalated"] == 1
    assert m["benign_investigated"] == 1
    assert m["benign_monitored"] == 0

    assert m["benign_escalation_rate"] == 0.5
    assert m["benign_investigation_rate"] == 0.5
    assert m["benign_monitoring_rate"] == 0.0

    # Policy overrides
    assert m["policy_overrides"] == 1
    assert m["policy_override_rate"] == pytest.approx(0.2)

    # Classification remains independent of final actions
    assert m["answered"] == 1
    assert m["reviewed"] == 4
    assert m["tp"] == 1
    assert m["accuracy_end_to_end"] == pytest.approx(0.2)


def test_successful_benign_monitoring():
    records = many(
        4,
        "benign",
        "benign",
        final_action="monitor",
        proposed_action="monitor",
    )

    m = compute_metrics(records)

    assert m["benign_monitored"] == 4
    assert m["benign_monitoring_rate"] == 1.0
    assert m["benign_escalation_rate"] == 0.0
    assert m["benign_investigation_rate"] == 0.0
    assert m["policy_overrides"] == 0


def test_malicious_event_monitored_counts_as_no_intervention():
    records = [
        rec(
            "malicious",
            "benign",
            final_action="monitor",
            proposed_action="monitor",
        )
    ]

    m = compute_metrics(records)

    assert m["malicious_monitored"] == 1
    assert m["malicious_escalation_rate"] == 0.0
    assert m["malicious_intervention_rate"] == 0.0


def test_failed_runs_excluded_from_operational_rates():
    records = [
        rec(
            "malicious",
            "malicious",
            final_action="escalate_for_review",
            proposed_action="escalate_for_review",
        ),
        rec(
            "malicious",
            None,
            status="failed",
            final_action=None,
            proposed_action=None,
        ),
        rec(
            "benign",
            "benign",
            final_action="monitor",
            proposed_action="monitor",
        ),
    ]

    m = compute_metrics(records)

    assert m["failed"] == 1
    assert m["operational_malicious_total"] == 1
    assert m["operational_benign_total"] == 1
    assert m["malicious_escalation_rate"] == 1.0
    assert m["benign_monitoring_rate"] == 1.0
    assert m["policy_override_rate"] == 0.0


def test_indeterminate_excluded_from_operational_class_rates():
    records = [
        rec(
            "indeterminate",
            "indeterminate",
            final_action="investigate",
            proposed_action="monitor",
        ),
        rec(
            "benign",
            "benign",
            final_action="monitor",
            proposed_action="monitor",
        ),
    ]

    m = compute_metrics(records)

    assert m["operational_malicious_total"] == 0
    assert m["operational_benign_total"] == 1

    # Overrides are measured across all successful scenarios,
    # including indeterminate ground truth.
    assert m["policy_overrides"] == 1
    assert m["policy_override_rate"] == pytest.approx(0.5)


def test_missing_final_action_is_rejected():
    records = [
        rec(
            "benign",
            "benign",
            final_action=None,
        )
    ]

    with pytest.raises(ValueError, match="final_action"):
        compute_metrics(records)


def test_invalid_final_action_is_rejected():
    records = [
        rec(
            "malicious",
            "malicious",
            final_action="delete_user",
        )
    ]

    with pytest.raises(ValueError, match="final_action"):
        compute_metrics(records)


def test_missing_proposed_action_is_rejected():
    records = [
        rec(
            "benign",
            "benign",
            proposed_action=None,
        )
    ]

    with pytest.raises(ValueError, match="proposed_action"):
        compute_metrics(records)


# -----------------------------------------------------------
# EDGE CASES
# -----------------------------------------------------------

def test_empty_and_degenerate_inputs_do_not_crash():
    m = compute_metrics([])

    assert m["total_scenarios"] == 0

    for key in (
        "precision",
        "recall",
        "f1",
        "accuracy_answered",
        "accuracy_end_to_end",
        "coverage",
        "injection_f1",
        "malicious_escalation_rate",
        "malicious_intervention_rate",
        "benign_monitoring_rate",
        "policy_override_rate",
    ):
        assert m[key] is None

    only_benign = compute_metrics(
        many(3, "benign", "benign")
    )

    assert only_benign["recall"] is None
    assert only_benign["precision"] is None
    assert only_benign["accuracy_answered"] == 1.0


def test_all_failed_run_reports_na_not_zero_accuracy_hiding_failures():
    m = compute_metrics(
        many(5, "benign", None, status="failed")
    )

    assert m["accuracy_answered"] is None
    assert m["accuracy_end_to_end"] == 0.0
    assert m["failed"] == 5

    # No successful operational decisions exist.
    assert m["operational_benign_total"] == 0
    assert m["benign_monitoring_rate"] is None
    assert m["policy_override_rate"] is None


def test_unknown_ground_truth_label_is_rejected():
    with pytest.raises(ValueError):
        compute_metrics([rec("maybe", "benign")])


@pytest.mark.parametrize(
    "assessment, expected",
    [
        ("suspicious", "suspicious"),
        ("benign", "benign"),
        ("uncertain", "indeterminate"),
        ("", "indeterminate"),
        (None, "indeterminate"),
    ],
)
def test_map_assessment(assessment, expected):
    assert map_assessment(assessment) == expected
