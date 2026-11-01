"""Read-only diagnostic: where does the injection scan hit, miss, and false-alarm?

Run from the project root:  python .\\injection_diagnostic.py

Ground truth is used only to score the results. The detector is given
get_detector_input(), the same leak-free event the systems see.
"""

import os
import sys

sys.path.insert(0, os.getcwd())

from detector import _normalize, detect_event
from scenarios import get_detector_input, get_ground_truth, list_scenarios

tp = fp = fn = tn = 0
misses, false_alarms = [], []

for scenario_id in list_scenarios():
    truth = get_ground_truth(scenario_id)
    event = get_detector_input(scenario_id)
    detected = detect_event(event)["injection_detected"]
    is_attack = truth["injection_label"] == "injection_attempt"

    if is_attack and detected:
        tp += 1
    elif is_attack:
        fn += 1
        long_text = {
            k: _normalize(v)[-100:]
            for k, v in event.items()
            if isinstance(v, str) and len(v) > 40
        }
        misses.append((scenario_id, long_text))
    elif detected:
        fp += 1
        false_alarms.append((scenario_id, truth["category"]))
    else:
        tn += 1

total = tp + fp + fn + tn
precision = tp / (tp + fp) if tp + fp else 0.0
recall = tp / (tp + fn) if tp + fn else 0.0
f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

print(f"Injection scan over {total} scenarios (detector only, no LLM)")
print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")
print(f"  precision={precision:.1%} recall={recall:.1%} F1={f1:.1%} accuracy={(tp + tn) / total:.1%}")
print("\nMissed injections:")
for scenario_id, fields in misses:
    print(f"  {scenario_id}: {fields}")
print("\nFalse alarms:")
for scenario_id, category in false_alarms:
    print(f"  {scenario_id}: {category}")