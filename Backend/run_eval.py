
from app.scenarios import list_scenarios, run_scenario, get_ground_truth
from app.detector import detect_event


def calculate_binary_metrics(actual, predicted, positive_label):
    """Calculate precision, recall, and F1 for one positive class."""
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
    injection_actual = []
    injection_predicted = []
    indeterminate_count = 0

    print("\nSYSTEM A: RULE-BASED DETECTOR EVALUATION")
    print("=" * 65)

    for scenario_id in list_scenarios():
        # The detector receives event data only.
        event = run_scenario(scenario_id)
        result = detect_event(event)

        # Ground truth is accessed only by this evaluation script.
        truth = get_ground_truth(scenario_id)

        actual = truth["label"]
        predicted = {
            "suspicious": "malicious",
            "benign": "benign",
        }.get(result["classification"], "indeterminate")

        actual_labels.append(actual)
        predicted_labels.append(predicted)

        injection_actual.append(
            truth["injection_label"] == "injection_attempt"
        )
        injection_predicted.append(result["injection_detected"])

        if predicted == "indeterminate":
            indeterminate_count += 1

        print(f"\nScenario: {scenario_id}")
        print(f"  Ground truth:          {actual}")
        print(f"  Detector classification: {result['classification']}")
        print(f"  Injection ground truth: {truth['injection_label']}")
        print(f"  Injection detected:    {result['injection_detected']}")

    total = len(actual_labels)
    correct = sum(
        actual == predicted
        for actual, predicted in zip(actual_labels, predicted_labels)
    )
    accuracy = correct / total if total else 0.0

    security_metrics = calculate_binary_metrics(
        actual_labels, predicted_labels, "malicious"
    )

    injection_metrics = calculate_binary_metrics(
        injection_actual, injection_predicted, True
    )

    print("\n" + "=" * 65)
    print("CLASSIFICATION METRICS")
    print("=" * 65)
    print(f"Scenarios evaluated: {total}")
    print(f"Correct classifications: {correct}/{total}")
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Indeterminate results: {indeterminate_count}")
    print(f"Malicious precision: {security_metrics['precision']:.2%}")
    print(f"Malicious recall:    {security_metrics['recall']:.2%}")
    print(f"Malicious F1-score:  {security_metrics['f1']:.2%}")
    print(
        "Confusion counts: "
        f"TP={security_metrics['TP']}, "
        f"FP={security_metrics['FP']}, "
        f"FN={security_metrics['FN']}, "
        f"TN={security_metrics['TN']}"
    )

    print("\nPROMPT-INJECTION METRICS")
    print("=" * 65)
    print(f"Precision: {injection_metrics['precision']:.2%}")
    print(f"Recall:    {injection_metrics['recall']:.2%}")
    print(f"F1-score:  {injection_metrics['f1']:.2%}")
    print(
        "Counts: "
        f"TP={injection_metrics['TP']}, "
        f"FP={injection_metrics['FP']}, "
        f"FN={injection_metrics['FN']}, "
        f"TN={injection_metrics['TN']}"
    )


if __name__ == "__main__":
    main()
