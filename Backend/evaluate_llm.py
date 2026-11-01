
from app.scenarios import list_scenarios, run_scenario, get_ground_truth
from app.llm_agent import analyze_event_with_llm


def calculate_metrics(actual, predicted, positive_label):
    tp = sum(
        a == positive_label and p == positive_label
        for a, p in zip(actual, predicted)
    )
    fp = sum(
        a != positive_label and p == positive_label
        for a, p in zip(actual, predicted)
    )
    fn = sum(
        a == positive_label and p != positive_label
        for a, p in zip(actual, predicted)
    )
    tn = sum(
        a != positive_label and p != positive_label
        for a, p in zip(actual, predicted)
    )

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main():
    actual_labels = []
    predicted_labels = []

    print("\nSYSTEM B: LLM-ONLY EVALUATION")
    print("=" * 65)
    print("Model:", __import__("app.llm_agent", fromlist=["MODEL"]).MODEL)

    for scenario_id in list_scenarios():
        event = run_scenario(scenario_id)

        print(f"\nAnalyzing: {scenario_id}")

        try:
            # Only the event is sent to DeepSeek.
            proposal = analyze_event_with_llm(event)

            # Ground truth is retrieved only after the model responds.
            truth = get_ground_truth(scenario_id)

            actual = truth["label"]
            predicted = {
                "suspicious": "malicious",
                "benign": "benign",
                "uncertain": "indeterminate",
            }[proposal["assessment"]]

            actual_labels.append(actual)
            predicted_labels.append(predicted)

            print("  Ground truth:", actual)
            print("  LLM assessment:", proposal["assessment"])
            print("  Mapped prediction:", predicted)
            print("  Severity:", proposal["severity"])
            print("  Confidence:", proposal["confidence"])
            print("  Recommended action:", proposal["recommended_action"])
            print("  Evidence:", proposal["evidence"])
            print("  Explanation:", proposal["explanation"])

            if truth["injection_label"] == "injection_attempt":
                print(
                    "  Injection scenario assessment:",
                    proposal["assessment"],
                )
                print(
                    "  Note: this schema does not return a separate "
                    "injection-detection field."
                )

        except Exception as exc:
            # Failed API calls or invalid model output are recorded as
            # indeterminate predictions rather than silently discarded.
            truth = get_ground_truth(scenario_id)
            actual_labels.append(truth["label"])
            predicted_labels.append("indeterminate")

            print("  ERROR:", type(exc).__name__, str(exc))
            print("  Prediction recorded as indeterminate.")

    total = len(actual_labels)
    correct = sum(
        a == p for a, p in zip(actual_labels, predicted_labels)
    )
    accuracy = correct / total if total else 0.0

    metrics = calculate_metrics(
        actual_labels, predicted_labels, "malicious"
    )

    print("\n" + "=" * 65)
    print("SYSTEM B CLASSIFICATION METRICS")
    print("=" * 65)
    print(f"Scenarios evaluated: {total}")
    print(f"Correct classifications: {correct}/{total}")
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Malicious precision: {metrics['precision']:.2%}")
    print(f"Malicious recall:    {metrics['recall']:.2%}")
    print(f"Malicious F1-score:  {metrics['f1']:.2%}")
    print(
        f"Confusion counts: TP={metrics['TP']}, "
        f"FP={metrics['FP']}, FN={metrics['FN']}, TN={metrics['TN']}"
    )
    print(
        "\nReminder: these results cover six predefined scenarios, "
        "not general real-world performance."
    )


if __name__ == "__main__":
    main()
