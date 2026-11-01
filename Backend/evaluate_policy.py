
"""System C evaluation: LLM proposal + deterministic policy.

Ground truth is read only after the system has made its decision.
All security actions remain simulated.
"""

import argparse
from collections import Counter

from app.scenarios import (
    get_detector_input,
    get_ground_truth,
    list_scenarios,
)

BINARY_LABELS = ("malicious", "benign")
ALL_LABELS = BINARY_LABELS + ("suspicious", "indeterminate")


def map_assessment(assessment):
    """Preserve the assessment instead of treating suspicious as malicious."""
    if assessment in {"malicious", "suspicious", "benign"}:
        return assessment
    return "indeterminate"


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def _f1(precision, recall):
    if precision is None or recall is None or precision + recall == 0:
        return None
    return 2 * precision * recall / (precision + recall)



def compute_metrics(records):
    """Compute classification, injection, safety, and operational metrics."""

    for record in records:
        if record["expected"] not in ALL_LABELS:
            raise ValueError(
                f"{record['scenario_id']}: unknown ground-truth label "
                f"{record['expected']!r}"
            )

    decidable = [
        r for r in records if r["expected"] in BINARY_LABELS
    ]
    undecidable = [
        r for r in records if r["expected"] == "indeterminate"
    ]
    ok = [r for r in records if r["status"] == "ok"]
    failed = [r for r in records if r["status"] == "failed"]

    def count(expected, predicted):
        return sum(
            1
            for r in decidable
            if r["status"] == "ok"
            and r["expected"] == expected
            and r["predicted"] == predicted
        )

    tp = count("malicious", "malicious")
    fp = count("benign", "malicious")
    fn = count("malicious", "benign")
    tn = count("benign", "benign")
    answered = tp + fp + fn + tn

    reviewed = [
        r for r in decidable
        if r["status"] == "ok" and r["predicted"] == "suspicious"
    ]
    abstained = [
        r for r in decidable
        if r["status"] == "ok" and r["predicted"] == "indeterminate"
    ]
    failed_decidable = [
        r for r in decidable if r["status"] == "failed"
    ]

    # Each decidable scenario must be accounted for exactly once.
    if (
        answered + len(reviewed) + len(abstained) + len(failed_decidable)
        != len(decidable)
    ):
        raise ValueError("Decidable scenarios do not reconcile.")

    malicious_total = sum(
        r["expected"] == "malicious" for r in decidable
    )
    correct = tp + tn

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)

    ind_ok = [r for r in undecidable if r["status"] == "ok"]
    ind_abstained = sum(
        r["predicted"] == "indeterminate" for r in ind_ok
    )

    def inj(expected, predicted):
        return sum(
            1 for r in ok
            if r["expected_injection"] == expected
            and r["predicted_injection"] == predicted
        )

    itp = inj(True, True)
    ifp = inj(False, True)
    ifn = inj(True, False)
    itn = inj(False, False)

    iprecision = _ratio(itp, itp + ifp)
    irecall = _ratio(itp, itp + ifn)


    allowed_final_actions = {
        "monitor",
        "investigate",
        "escalate_for_review",
    }

    # Validate all successful records, including indeterminate cases.
    for r in ok:
        if r.get("final_action") not in allowed_final_actions:
            raise ValueError(
                f"{r['scenario_id']}: missing or invalid final_action "
                f"{r.get('final_action')!r}"
            )

        if r.get("proposed_action") not in allowed_final_actions:
            raise ValueError(
                f"{r['scenario_id']}: missing or invalid proposed_action "
                f"{r.get('proposed_action')!r}"
            )

    # Only successful, decidable records are used for
    # ground-truth operational rates.

    operational_ok = [
        r for r in ok
        if r["expected"] in BINARY_LABELS
    ]

    malicious_ok = [
        r for r in operational_ok
        if r["expected"] == "malicious"
    ]

    benign_ok = [
        r for r in operational_ok
        if r["expected"] == "benign"
    ]

    def action_count(group, action):
        return sum(
            r["final_action"] == action
            for r in group
        )

    malicious_escalated = action_count(
        malicious_ok, "escalate_for_review"
    )
    malicious_investigated = action_count(
        malicious_ok, "investigate"
    )
    malicious_monitored = action_count(
        malicious_ok, "monitor"
    )

    benign_escalated = action_count(
        benign_ok, "escalate_for_review"
    )
    benign_investigated = action_count(
        benign_ok, "investigate"
    )
    benign_monitored = action_count(
        benign_ok, "monitor"
    )

    # The policy override rate includes all successfully evaluated
    # scenarios, including ground-truth indeterminate records.
    policy_overrides = sum(
        r["final_action"] != r["proposed_action"]
        for r in ok
    )

    # -----------------------------------------------------------
    # RETURN ALL METRICS
    # -----------------------------------------------------------

    return {
        "total_scenarios": len(records),
        "ran_ok": len(ok),
        "failed": len(failed),
        "failed_ids": [r["scenario_id"] for r in failed],
        "decidable_total": len(decidable),
        "undecidable_total": len(undecidable),
        "answered": answered,
        "reviewed": len(reviewed),
        "reviewed_malicious": sum(
            r["expected"] == "malicious" for r in reviewed
        ),
        "reviewed_benign": sum(
            r["expected"] == "benign" for r in reviewed
        ),
        "abstained": len(abstained),
        "abstained_malicious": sum(
            r["expected"] == "malicious" for r in abstained
        ),
        "abstained_benign": sum(
            r["expected"] == "benign" for r in abstained
        ),
        "abstained_raw": dict(
            Counter(str(r["raw_assessment"]) for r in abstained)
        ),
        "failed_decidable": len(failed_decidable),
        "failed_decidable_malicious": sum(
            r["expected"] == "malicious" for r in failed_decidable
        ),
        "failed_decidable_benign": sum(
            r["expected"] == "benign" for r in failed_decidable
        ),
        "malicious_total": malicious_total,

        # Binary classification
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": _f1(precision, recall),
        "accuracy_answered": _ratio(correct, answered),
        "accuracy_excluding_failures": _ratio(
            correct, len(decidable) - len(failed_decidable)
        ),
        "accuracy_end_to_end": _ratio(correct, len(decidable)),
        "coverage": _ratio(answered, len(decidable)),
        "recall_end_to_end": _ratio(tp, malicious_total),

        # Malformed or indeterminate records
        "indeterminate_ran": len(ind_ok),
        "indeterminate_abstained": ind_abstained,
        "indeterminate_forced_malicious": sum(
            r["predicted"] == "malicious" for r in ind_ok
        ),
        "indeterminate_forced_benign": sum(
            r["predicted"] == "benign" for r in ind_ok
        ),
        "indeterminate_failed": len(undecidable) - len(ind_ok),

        # Prompt-injection detection
        "injection_scored": len(ok),
        "injection_tp": itp,
        "injection_fp": ifp,
        "injection_fn": ifn,
        "injection_tn": itn,
        "injection_accuracy": _ratio(itp + itn, len(ok)),
        "injection_precision": iprecision,
        "injection_recall": irecall,
        "injection_f1": _f1(iprecision, irecall),
        "injection_detected_count": sum(
            r["predicted_injection"] for r in ok
        ),

        # Existing safety metrics
        "actions_changed": sum(r["action_changed"] for r in ok),
        "execution_violations": sum(
            r["execution_violation"] for r in ok
        ),

        # NEW: Operational counts
        "operational_malicious_total": len(malicious_ok),
        "operational_benign_total": len(benign_ok),
        "malicious_escalated": malicious_escalated,
        "malicious_investigated": malicious_investigated,
        "malicious_monitored": malicious_monitored,
        "benign_escalated": benign_escalated,
        "benign_investigated": benign_investigated,
        "benign_monitored": benign_monitored,

        # NEW: Operational rates
        "malicious_escalation_rate": _ratio(
            malicious_escalated, len(malicious_ok)
        ),
        "malicious_intervention_rate": _ratio(
            malicious_escalated + malicious_investigated,
            len(malicious_ok)
        ),
        "benign_investigation_rate": _ratio(
            benign_investigated, len(benign_ok)
        ),
        "benign_escalation_rate": _ratio(
            benign_escalated, len(benign_ok)
        ),
        "benign_monitoring_rate": _ratio(
            benign_monitored, len(benign_ok)
        ),
        "policy_overrides": policy_overrides,
        "policy_override_rate": _ratio(
            policy_overrides, len(ok)
        ),
    }


def _pct(value):
    return "n/a" if value is None else f"{value:.2%}"



def print_report(m):
    line = "=" * 75
    print("\n" + line)
    print("SYSTEM C RESULTS")
    print(line)

    # -----------------------------------------------------------
    # 1. SCENARIO ACCOUNTING
    # -----------------------------------------------------------
    print("\nSCENARIO ACCOUNTING")
    print(f"  Total scenarios:                       {m['total_scenarios']}")
    print(f"  Ground truth malicious/benign:         {m['decidable_total']}")
    print(f"    Binary classifications:              {m['answered']}")
    print(
        f"    Routed for review (suspicious):      {m['reviewed']}"
        f" [malicious={m['reviewed_malicious']}, "
        f"benign={m['reviewed_benign']}]"
    )
    print(
        f"    Abstained:                           {m['abstained']}"
        f" [malicious={m['abstained_malicious']}, "
        f"benign={m['abstained_benign']}]"
    )
    if m["abstained_raw"]:
        print(f"      Raw assessments abstained on:       {m['abstained_raw']}")
    print(
        f"    Failed:                              {m['failed_decidable']}"
        f" [malicious={m['failed_decidable_malicious']}, "
        f"benign={m['failed_decidable_benign']}]"
    )
    print(f"  Ground truth indeterminate:            {m['undecidable_total']}")

    # -----------------------------------------------------------
    # 2. BINARY CLASSIFICATION
    # -----------------------------------------------------------
    print("\nBINARY CLASSIFICATION (malicious vs benign)")
    print(f"  TP={m['tp']}, FP={m['fp']}, FN={m['fn']}, TN={m['tn']}")
    print(f"  Malicious precision:                   {_pct(m['precision'])}")
    print(f"  Malicious recall (answered):           {_pct(m['recall'])}")
    print(f"  Malicious F1-score:                    {_pct(m['f1'])}")
    print(
        f"  Malicious recall (end to end):         "
        f"{_pct(m['recall_end_to_end'])}"
        f" (TP / all {m['malicious_total']} malicious scenarios)"
    )

    # -----------------------------------------------------------
    # 3. CLASSIFICATION ACCURACY
    # -----------------------------------------------------------
    print("\nACCURACY")
    print(
        f"  Binary classifications only:           "
        f"{_pct(m['accuracy_answered'])}"
        f" ({m['tp'] + m['tn']}/{m['answered']})"
    )
    print(
        f"  Excluding failures:                    "
        f"{_pct(m['accuracy_excluding_failures'])}"
        f" ({m['tp'] + m['tn']}/"
        f"{m['decidable_total'] - m['failed_decidable']})"
    )
    print(
        f"  End to end:                            "
        f"{_pct(m['accuracy_end_to_end'])}"
        f" ({m['tp'] + m['tn']}/{m['decidable_total']})"
    )
    print(
        f"  Binary classification coverage:        "
        f"{_pct(m['coverage'])}"
    )

    # -----------------------------------------------------------
    # 4. OPERATIONAL SECURITY PERFORMANCE (NEW)
    # -----------------------------------------------------------
    print("\nOPERATIONAL SECURITY PERFORMANCE")
    print("-" * 75)

    print(
        f"  Malicious events evaluated:            "
        f"{m['operational_malicious_total']}"
    )
    print(
        f"  Benign events evaluated:               "
        f"{m['operational_benign_total']}"
    )

    print("\n  MALICIOUS EVENT HANDLING")
    print(
        f"    Escalated for review:                "
        f"{m['malicious_escalated']}"
    )
    print(
        f"    Sent for investigation:              "
        f"{m['malicious_investigated']}"
    )
    print(
        f"    Monitored without intervention:      "
        f"{m['malicious_monitored']}"
    )
    print(
        f"    Malicious escalation rate:           "
        f"{_pct(m['malicious_escalation_rate'])}"
    )
    print(
        f"    Malicious intervention rate:         "
        f"{_pct(m['malicious_intervention_rate'])}"
    )

    print("\n  BENIGN EVENT HANDLING")
    print(
        f"    Escalated for review:                "
        f"{m['benign_escalated']}"
    )
    print(
        f"    Sent for investigation:              "
        f"{m['benign_investigated']}"
    )
    print(
        f"    Monitored without intervention:      "
        f"{m['benign_monitored']}"
    )
    print(
        f"    Benign investigation rate:           "
        f"{_pct(m['benign_investigation_rate'])}"
    )
    print(
        f"    Benign escalation rate:              "
        f"{_pct(m['benign_escalation_rate'])}"
    )
    print(
        f"    Benign monitoring rate:              "
        f"{_pct(m['benign_monitoring_rate'])}"
    )

    print("\n  POLICY OVERRIDES")
    print(
        f"    Total policy overrides:              "
        f"{m['policy_overrides']}"
    )
    print(
        f"    Policy override rate:                "
        f"{_pct(m['policy_override_rate'])}"
    )

    print(
        "\n  Note: Operational rates exclude failed runs and "
        "ground-truth indeterminate events."
    )
    print(
        "  An investigation or escalation is not the same "
        "as a correct binary classification."
    )

    # -----------------------------------------------------------
    # 5. MALFORMED RECORDS
    # -----------------------------------------------------------
    print("\nMALFORMED RECORDS")
    print(
        f"  Ran: {m['indeterminate_ran']}, "
        f"abstained: {m['indeterminate_abstained']}, "
        f"forced malicious: {m['indeterminate_forced_malicious']}, "
        f"forced benign: {m['indeterminate_forced_benign']}, "
        f"failed: {m['indeterminate_failed']}"
    )

    # -----------------------------------------------------------
    # 6. PROMPT-INJECTION DETECTION
    # -----------------------------------------------------------
    print(
        "\nPROMPT-INJECTION DETECTION "
        f"(scored on {m['injection_scored']} scenarios that ran)"
    )
    print(
        f"  Accuracy:                              "
        f"{_pct(m['injection_accuracy'])}"
    )
    print(
        f"  Precision:                             "
        f"{_pct(m['injection_precision'])}"
    )
    print(
        f"  Recall:                                "
        f"{_pct(m['injection_recall'])}"
    )
    print(
        f"  F1-score:                              "
        f"{_pct(m['injection_f1'])}"
    )
    print(
        f"  TP={m['injection_tp']}, FP={m['injection_fp']}, "
        f"FN={m['injection_fn']}, TN={m['injection_tn']}"
    )

    # -----------------------------------------------------------
    # 7. POLICY AND SAFETY
    # -----------------------------------------------------------
    print("\nPOLICY AND SAFETY")
    print(
        f"  Scenarios with injection detected:     "
        f"{m['injection_detected_count']}"
    )
    print(
        f"  Actions changed by policy:             "
        f"{m['actions_changed']}"
    )
    print(
        f"  Execution-safety violations:           "
        f"{m['execution_violations']}"
    )
    print(
        f"  Failed scenarios:                      "
        f"{m['failed']}"
    )

    for scenario_id in m["failed_ids"]:
        print(f"    - {scenario_id}")



def print_false_positives(records):
    """Print benign scenarios classified as malicious."""
    false_positives = [
        r for r in records
        if r["status"] == "ok"
        and r["expected"] == "benign"
        and r["predicted"] == "malicious"
    ]

    print("\n" + "=" * 75)
    print(f"FALSE POSITIVE ANALYSIS: {len(false_positives)} scenarios")
    print("=" * 75)

    if not false_positives:
        print("No false positives found.")
        return

    for record in false_positives:
        print(f"\nScenario: {record['scenario_id']}")
        print(f"  Expected:          {record['expected']}")
        print(f"  Predicted:         {record['predicted']}")
        print(f"  LLM assessment:    {record.get('raw_assessment')}")
        print(f"  LLM proposed:      {record.get('llm_action')}")
        print(f"  LLM evidence:      {record.get('llm_evidence')}")
        print(f"  LLM explanation:   {record.get('llm_explanation')}")
        print(f"  Policy final:      {record.get('final_action')}")
        print(f"  Policy approved:   {record.get('approved')}")


def main(scenario_ids=None):
    # Local imports allow metric tests to run without initializing the LLM.
    from app.llm_agent import analyze_event_with_llm
    from app.policy import apply_policy
    from app.detector import detect_event

    print("\nSYSTEM C: LLM + POLICY EVALUATION")
    print("=" * 75)

    records = []
    selected_scenarios = (
        list_scenarios() if scenario_ids is None else scenario_ids
    )

    for scenario_id in selected_scenarios:
        event = get_detector_input(scenario_id)
        print(f"\nScenario: {scenario_id}")

        record = {
            "scenario_id": scenario_id,
            "status": "ok",
            "error": None,
            "predicted": None,
            "raw_assessment": None,
            "predicted_injection": False,
            "action_changed": False,
            "execution_violation": False,
            "llm_evidence": None,
            "llm_explanation": None,
            "llm_action": None,
            "proposed_action": None,
            "final_action": None,
            "approved": None,
            "executed": None,
        }

        try:
            detector_result = detect_event(event)
            print(
                f"  System A: {detector_result['classification']} "
                f"| severity={detector_result['severity']}"
            )

            proposal = analyze_event_with_llm(event, detector_result)
            policy_result = apply_policy(event, proposal, detector_result)

            # Build all decision fields together after both calls succeed.
            record.update(
                raw_assessment=proposal["assessment"],
                llm_evidence=proposal.get("evidence"),
                llm_explanation=proposal.get("explanation"),
                predicted=map_assessment(proposal["assessment"]),
                predicted_injection=bool(policy_result["injection_detected"]),
                action_changed=(
                    policy_result["proposed_action"]
                    != policy_result["final_action"]
                ),
                execution_violation=(policy_result.get("executed") is not False),
                llm_action=proposal["recommended_action"],
                proposed_action=policy_result["proposed_action"],
                final_action=policy_result["final_action"],
                approved=policy_result["approved"],
                executed=policy_result["executed"],
            )
        except Exception as exc:
            # The LLM or policy might have failed before policy_result exists.
            # Failed records are excluded from operational decision metrics.
            record.update(
                status="failed",
                error=f"{type(exc).__name__}: {exc}",
                predicted=None,
                proposed_action=None,
                final_action=None,
            )

        # Read ground truth only after the system's decision or failure.
        truth = get_ground_truth(scenario_id)
        record["expected"] = truth["label"]
        record["expected_injection"] = (
            truth["injection_label"] == "injection_attempt"
        )
        records.append(record)

        print("  Ground truth:", record["expected"])
        if record["status"] == "failed":
            print("  Evaluation error:", record["error"])
        else:
            print("  LLM assessment:", record["raw_assessment"])
            print("  Predicted class:", record["predicted"])
            print("  LLM proposed action:", record["llm_action"])
            print("  Policy final action:", record["final_action"])
            print("  Policy approved proposal:", record["approved"])
            print("  Injection detected:", record["predicted_injection"])
            print("  Action executed:", record["executed"])

    print_report(compute_metrics(records))
    print_false_positives(records)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate System C on all or selected scenarios."
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        help="Scenario IDs to evaluate. Defaults to all scenarios.",
    )
    args = parser.parse_args()

    available = set(list_scenarios())

    if args.scenarios:
        unknown = set(args.scenarios) - available
        if unknown:
            parser.error(
                f"Unknown scenario IDs: {', '.join(sorted(unknown))}"
            )

    main(scenario_ids=args.scenarios)
